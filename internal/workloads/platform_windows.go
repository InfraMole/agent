// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package workloads

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	// Local transports: shared memory (default in every edition) and named pipes.
	_ "github.com/microsoft/go-mssqldb/namedpipe"
	_ "github.com/microsoft/go-mssqldb/sharedmemory"
	"golang.org/x/sys/windows/registry"

	"github.com/InfraMole/agent/internal/health"
	"github.com/InfraMole/agent/internal/protocol"
)

const (
	Supported = true
	onWindows = true
	onLinux   = false
)

// Linux workloads do not exist on Windows.
func nginxSites() ([]protocol.WebSite, bool, error)   { return nil, false, nil }
func apacheSites() ([]protocol.WebSite, bool, error)  { return nil, false, nil }
func haproxySites() ([]protocol.WebSite, bool, error) { return nil, false, nil }
func postgresDatabases(context.Context) ([]protocol.Database, bool, error) {
	return nil, false, nil
}
func mysqlDatabases(context.Context) ([]protocol.Database, bool, error) { return nil, false, nil }
func postgresClients(context.Context) ([]protocol.DatabaseClient, bool, error) {
	return nil, false, nil
}
func mysqlClients(context.Context) ([]protocol.DatabaseClient, bool, error) { return nil, false, nil }

// iisSites reads %windir%\System32\inetsrv\config\applicationHost.config.
// found=false when IIS is not installed.
func iisSites() ([]protocol.WebSite, bool, error) {
	path := filepath.Join(os.Getenv("windir"), "System32", "inetsrv", "config", "applicationHost.config")
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	sites, err := ParseApplicationHost(f)
	if err != nil {
		return nil, false, fmt.Errorf("read applicationHost.config: %w", err)
	}
	// M25: reverse-proxy targets (ARR). Best effort: never fails the sites.
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		if conf, err := parseIISProxies(f); err == nil {
			for i := range sites {
				urls := append(append([]string{}, conf.global...), conf.bySite[sites[i].Name]...)
				if root := conf.roots[sites[i].Name]; root != "" {
					if wc, err := os.Open(filepath.Join(os.ExpandEnv(expandWinEnv(root)), "web.config")); err == nil {
						urls = append(urls, webConfigRewrites(io.LimitReader(wc, maxConfigBytes))...)
						wc.Close()
					}
				}
				sites[i].Upstreams = iisUpstreams(urls, conf.farms)
			}
		}
	}
	return sites, true, nil
}

// NewSiteResolver attributes IIS worker processes to their site (M42):
// `appcmd list wp` gives each worker's application pool, applicationHost.config
// the sites of each pool. Nil when IIS is not installed.
func NewSiteResolver(log *slog.Logger) func(int32, string) string {
	inetsrv := filepath.Join(os.Getenv("windir"), "System32", "inetsrv")
	appcmd := filepath.Join(inetsrv, "appcmd.exe")
	if _, err := os.Stat(appcmd); err != nil {
		return nil
	}
	r := &siteResolver{now: time.Now, log: log, list: func() (map[int32]string, map[string][]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, appcmd, "list", "wp", "/xml").Output()
		if err != nil {
			return nil, nil, fmt.Errorf("appcmd list wp: %w", err)
		}
		f, err := os.Open(filepath.Join(inetsrv, "config", "applicationHost.config"))
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		pools, err := ParsePoolSites(f)
		if err != nil {
			return nil, nil, fmt.Errorf("read applicationHost.config: %w", err)
		}
		return ParseWorkerProcesses(out), pools, nil
	}}
	return r.resolve
}

// expandWinEnv turns IIS's %SystemDrive%-style variables into $VAR for os.ExpandEnv.
func expandWinEnv(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "%")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i+1:], "%")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString("${" + s[i+1:i+1+j] + "}")
		s = s[i+2+j:]
	}
}

// sqlDatabases lists user database names of every local SQL Server instance,
// connecting with the service's Windows identity (integrated authentication:
// no credentials are stored). Only `SELECT name FROM sys.databases` is run.
func sqlDatabases(ctx context.Context) ([]protocol.Database, error) {
	instances, err := sqlInstances()
	if err != nil {
		return nil, err
	}
	var out []protocol.Database
	var errs []error
	for _, inst := range instances {
		names, err := databaseNames(ctx, inst)
		if err != nil {
			errs = append(errs, fmt.Errorf("instance %s: %w", inst, err))
			continue
		}
		for _, n := range names {
			out = append(out, protocol.Database{Instance: clip(inst, 128), Name: clip(n, 128)})
		}
	}
	// Report what we could read; fail only when no instance answered.
	if len(errs) > 0 && len(errs) == len(instances) {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// sqlInstances: value names under "Instance Names\SQL" (MSSQLSERVER = default).
func sqlInstances() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadValueNames(0)
}

func databaseNames(ctx context.Context, instance string) ([]string, error) {
	return listDatabases(ctx, instanceDSN(instance))
}

// instanceDSN: a local connection to one instance with the service's own
// Windows identity.
func instanceDSN(instance string) string {
	host := "localhost"
	q := url.Values{}
	q.Set("database", "master")
	q.Set("app name", "inframole-agent")
	q.Set("dial timeout", "10")
	// Local only (shared memory / named pipe / loopback): the login is
	// encrypted, and an instance that forces TLS with its self-signed
	// certificate still works — nothing leaves the machine.
	q.Set("encrypt", "false")
	q.Set("TrustServerCertificate", "true")
	u := &url.URL{Scheme: "sqlserver", Host: host, RawQuery: q.Encode()}
	if !strings.EqualFold(instance, "MSSQLSERVER") {
		u.Path = instance
	}
	return u.String()
}

// sqlClients (M42): per local instance, the remote clients with sessions
// open to user databases. found=false when SQL Server is not installed.
func sqlClients(ctx context.Context) ([]protocol.DatabaseClient, bool, error) {
	instances, err := sqlInstances()
	if err != nil || len(instances) == 0 {
		return nil, false, err
	}
	var out []protocol.DatabaseClient
	var errs []error
	for _, inst := range instances {
		rows, err := listClients(ctx, instanceDSN(inst))
		if err != nil {
			errs = append(errs, fmt.Errorf("instance %s: %w", inst, err))
			continue
		}
		out = append(out, toClients("mssql", inst, rows)...)
	}
	// Report what we could read; fail only when no instance answered.
	if len(errs) > 0 && len(errs) == len(instances) {
		return nil, true, errors.Join(errs...)
	}
	return out, true, nil
}

// The permission check and the one query behind database clients (M42).
// Without VIEW SERVER STATE (or, from SQL Server 2022, VIEW SERVER
// PERFORMANCE STATE) the session list shows only the agent's own session,
// which would read as "nobody uses these databases".
const (
	clientsPermission     = `SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER STATE')`
	clientsPermission2022 = `SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER PERFORMANCE STATE')`
	clientsQuery          = `SELECT d.name, c.client_net_address, c.local_tcp_port, COUNT(DISTINCT s.session_id)
FROM sys.dm_exec_sessions AS s
JOIN sys.dm_exec_connections AS c ON c.session_id = s.session_id
JOIN sys.databases AS d ON d.database_id = s.database_id
WHERE s.is_user_process = 1 AND s.session_id <> @@SPID AND s.database_id > 4
  AND c.net_transport = 'TCP' AND c.local_tcp_port IS NOT NULL
GROUP BY d.name, c.client_net_address, c.local_tcp_port`
)

func listClients(ctx context.Context, dsn string) ([]clientRow, error) {
	connector, err := mssql.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !hasPermission(ctx, db, clientsPermission) && !hasPermission(ctx, db, clientsPermission2022) {
		return nil, fmt.Errorf("VIEW SERVER STATE not granted: %w", health.ErrAccessDenied)
	}
	rows, err := db.QueryContext(ctx, clientsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []clientRow
	for rows.Next() {
		var r clientRow
		if err := rows.Scan(&r.database, &r.address, &r.port, &r.sessions); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// hasPermission: a NULL answer (a permission this version does not know)
// or an error counts as not granted.
func hasPermission(ctx context.Context, db *sql.DB, query string) bool {
	var granted sql.NullInt64
	return db.QueryRowContext(ctx, query).Scan(&granted) == nil && granted.Valid && granted.Int64 == 1
}

// listDatabases runs the query behind database names.
func listDatabases(ctx context.Context, dsn string) ([]string, error) {
	connector, err := mssql.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// database_id 1–4 are master, tempdb, model and msdb.
	rows, err := db.QueryContext(ctx, "SELECT name FROM sys.databases WHERE database_id > 4 ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
