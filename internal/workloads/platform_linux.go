// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package workloads

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

const (
	Supported = true
	onWindows = false
	onLinux   = true
)

// Windows workloads do not exist on Linux.
func iisSites() ([]protocol.WebSite, bool, error)               { return nil, false, nil }
func sqlDatabases(context.Context) ([]protocol.Database, error) { return nil, nil }

// nginxSites reads /etc/nginx/nginx.conf and its includes. found=false when
// nginx is not installed.
func nginxSites() ([]protocol.WebSite, bool, error) {
	return webConfig(ParseNginx, "/etc/nginx/nginx.conf")
}

// apacheSites reads the Debian (apache2) or RHEL (httpd) layout.
func apacheSites() ([]protocol.WebSite, bool, error) {
	return webConfig(ParseApache, "/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf")
}

func webConfig(parse func(fs.FS, string) ([]protocol.WebSite, error), candidates ...string) ([]protocol.WebSite, bool, error) {
	for _, main := range candidates {
		if _, err := os.Stat(main); err != nil {
			continue
		}
		sites, err := parse(os.DirFS("/"), main)
		if err != nil {
			return nil, false, fmt.Errorf("read %s: %w", main, err)
		}
		return sites, true, nil
	}
	return nil, false, nil
}

// postgresDatabases asks every local PostgreSQL cluster (one Unix socket per
// port) for its database names, logging in as the agent's OS user with peer
// authentication. found=false when no PostgreSQL socket exists.
func postgresDatabases(ctx context.Context) ([]protocol.Database, bool, error) {
	var sockets []string
	for _, dir := range []string{"/var/run/postgresql", "/run/postgresql", "/tmp"} {
		matches, _ := filepath.Glob(filepath.Join(dir, ".s.PGSQL.*"))
		for _, m := range matches {
			if !strings.HasSuffix(m, ".lock") {
				sockets = append(sockets, m)
			}
		}
	}
	sockets = uniqueTargets(sockets)
	if len(sockets) == 0 {
		return nil, false, nil
	}
	who, err := osUser()
	if err != nil {
		return nil, true, err
	}
	var out []protocol.Database
	var errs []error
	for _, sock := range sockets {
		port := sock[strings.LastIndex(sock, ".")+1:]
		names, err := onSocket(ctx, sock, func(c net.Conn) ([]string, error) { return pgListDatabases(c, who) })
		if err != nil {
			errs = append(errs, fmt.Errorf("port %s: %w", port, err))
			continue
		}
		for _, n := range names {
			if !pgSystem[n] {
				out = append(out, protocol.Database{Instance: clip(port, 128), Name: clip(n, 128)})
			}
		}
	}
	if len(errs) > 0 && len(errs) == len(sockets) {
		return nil, true, errors.Join(errs...)
	}
	return out, true, nil
}

// mysqlDatabases asks the local MySQL / MariaDB server for its database
// names, logging in as the agent's OS user with socket authentication.
// found=false when no socket exists.
func mysqlDatabases(ctx context.Context) ([]protocol.Database, bool, error) {
	var sockets []string
	for _, s := range []string{"/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/var/lib/mysql/mysql.sock", "/tmp/mysql.sock"} {
		if fi, err := os.Stat(s); err == nil && fi.Mode()&os.ModeSocket != 0 {
			sockets = append(sockets, s)
		}
	}
	sockets = uniqueTargets(sockets)
	if len(sockets) == 0 {
		return nil, false, nil
	}
	who, err := osUser()
	if err != nil {
		return nil, true, err
	}
	names, err := onSocket(ctx, sockets[0], func(c net.Conn) ([]string, error) { return mysqlListDatabases(c, who) })
	if err != nil {
		return nil, true, err
	}
	out := make([]protocol.Database, 0, len(names))
	for _, n := range names {
		if !mysqlSystem[n] {
			out = append(out, protocol.Database{Instance: "default", Name: clip(n, 128)})
		}
	}
	return out, true, nil
}

// System databases are never reported (data minimisation; the server
// filters them too).
var (
	pgSystem    = map[string]bool{"postgres": true, "template0": true, "template1": true}
	mysqlSystem = map[string]bool{"information_schema": true, "mysql": true, "performance_schema": true, "sys": true}
)

// onSocket dials a local Unix socket with a deadline and runs one exchange.
func onSocket(ctx context.Context, path string, fn func(net.Conn) ([]string, error)) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return fn(conn)
}

// uniqueTargets drops paths that resolve to the same file (/var/run → /run).
func uniqueTargets(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			real = p
		}
		if !seen[real] {
			seen[real] = true
			out = append(out, p)
		}
	}
	return out
}

func osUser() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
