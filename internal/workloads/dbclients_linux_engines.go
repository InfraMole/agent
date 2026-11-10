// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/InfraMole/agent/internal/health"
	"github.com/InfraMole/agent/internal/protocol"
)

// Database clients on Linux (M45, ADR-061): who has sessions open to the
// local PostgreSQL and MySQL / MariaDB databases, read from the engine's own
// session list over the M20 login (local socket, the agent's OS user, never
// a password). Database, client address, server port and a count only —
// never role or user names, application names, commands or statements.

// System databases are never reported (data minimisation; the server
// filters them too).
var (
	pgSystem    = map[string]bool{"postgres": true, "template0": true, "template1": true}
	mysqlSystem = map[string]bool{"information_schema": true, "mysql": true, "performance_schema": true, "sys": true}
)

// Without pg_read_all_stats, other roles' rows hide client_addr: the list
// would read as "nobody uses these databases", so it is refused instead.
const (
	pgClientsPermission = `SELECT pg_has_role(current_user, 'pg_read_all_stats', 'USAGE')`
	pgClientsQuery      = `SELECT datname, host(client_addr), count(*) FROM pg_stat_activity
WHERE backend_type = 'client backend' AND client_addr IS NOT NULL AND datname IS NOT NULL
  AND pid <> pg_backend_pid()
GROUP BY 1, 2`
)

// pgSessionClients lists the remote clients of one PostgreSQL cluster
// (instance = its port, as in the workloads import).
func pgSessionClients(conn io.ReadWriter, user string, port int) ([]protocol.DatabaseClient, error) {
	results, err := pgQuery(conn, user, pgClientsPermission, pgClientsQuery)
	if err != nil {
		return nil, err
	}
	if len(results[0]) != 1 || len(results[0][0]) != 1 || results[0][0][0] != "t" {
		return nil, fmt.Errorf("pg_read_all_stats not granted: %w", health.ErrAccessDenied)
	}
	var rows []clientRow
	for _, r := range results[1] {
		if len(r) != 3 || pgSystem[r[0]] {
			continue
		}
		n, _ := strconv.Atoi(r[2])
		rows = append(rows, clientRow{database: r[0], address: r[1], port: port, sessions: n})
	}
	return toClients("postgresql", strconv.Itoa(port), rows), nil
}

// MySQL / MariaDB: with performance_schema on, client sockets give exact
// IPs even when the server resolves client names; otherwise PROCESSLIST,
// whose host is kept only when it is an IP literal (names are never
// resolved by the agent). PROCESSLIST shows other users' sessions only
// with PROCESS.
const (
	mySettings     = `SELECT @@performance_schema, @@port`
	myClientsPerfQ = `SELECT t.PROCESSLIST_DB, s.IP, COUNT(*)
FROM performance_schema.socket_instances AS s
JOIN performance_schema.threads AS t ON t.THREAD_ID = s.THREAD_ID
WHERE s.EVENT_NAME = 'wait/io/socket/sql/client_connection' AND s.IP <> ''
  AND t.PROCESSLIST_DB IS NOT NULL AND t.PROCESSLIST_ID <> CONNECTION_ID()
GROUP BY t.PROCESSLIST_DB, s.IP`
	myProcessPrivilege = `SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE = 'PROCESS' AND GRANTEE = CONCAT('''', SUBSTRING_INDEX(CURRENT_USER(), '@', 1), '''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')`
	myClientsListQ = `SELECT DB, HOST FROM information_schema.PROCESSLIST
WHERE DB IS NOT NULL AND ID <> CONNECTION_ID()`
)

// mySessionClients lists the remote clients of the local MySQL / MariaDB
// server (instance "default", as in the workloads import).
func mySessionClients(conn io.ReadWriter, user string) ([]protocol.DatabaseClient, error) {
	c, err := mysqlLogin(conn, user)
	if err != nil {
		return nil, err
	}
	defer c.quit()
	settings, err := c.query(mySettings)
	if err != nil {
		return nil, err
	}
	if len(settings) != 1 || len(settings[0]) != 2 {
		return nil, errors.New("mysql: unexpected settings")
	}
	port, _ := strconv.Atoi(settings[0][1])

	var rows []clientRow
	add := func(db, address string, sessions int) {
		if !mysqlSystem[db] {
			rows = append(rows, clientRow{database: db, address: address, port: port, sessions: sessions})
		}
	}
	perf := false
	if settings[0][0] == "1" {
		list, err := c.query(myClientsPerfQ)
		var refused *myServerError
		switch {
		case err == nil:
			perf = true
			for _, r := range list {
				if len(r) == 3 {
					n, _ := strconv.Atoi(r[2])
					add(r[0], r[1], n)
				}
			}
		case !errors.As(err, &refused): // the session is gone
			return nil, err
		}
		// Refused (no SELECT on those tables): try PROCESSLIST.
	}
	if !perf {
		granted, err := c.query(myProcessPrivilege)
		if err != nil {
			return nil, err
		}
		if len(granted) != 1 || len(granted[0]) != 1 || granted[0][0] == "0" {
			return nil, fmt.Errorf("PROCESS not granted: %w", health.ErrAccessDenied)
		}
		list, err := c.query(myClientsListQ)
		if err != nil {
			return nil, err
		}
		for _, r := range list {
			if len(r) == 2 {
				if addr, ok := processlistAddress(r[1]); ok {
					add(r[0], addr, 1)
				}
			}
		}
	}
	return toClients("mysql", "default", rows), nil
}

// processlistAddress extracts the client IP from a PROCESSLIST host
// ("10.0.0.5:51234", "[2001:db8::5]:51234", "::ffff:10.0.0.5:51234"); a
// name ("app01:51234", "localhost") is not an address.
func processlistAddress(host string) (string, bool) {
	i := strings.LastIndexByte(host, ':')
	if i <= 0 {
		return "", false
	}
	h := strings.TrimSuffix(strings.TrimPrefix(host[:i], "["), "]")
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return "", false
	}
	return addr.String(), true
}
