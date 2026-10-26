// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows && mssqllive

package workloads

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"

	"github.com/InfraMole/agent/internal/health"
)

// Live check of the database query against a real SQL Server (manual):
//
//	INFRAMOLE_TEST_MSSQL_DSN="sqlserver://sa:<pw>@localhost:14333" go test -tags mssqllive ./internal/workloads
//
// The agent itself never uses SQL logins: it connects with its Windows identity.
func TestListDatabasesLive(t *testing.T) {
	dsn := os.Getenv("INFRAMOLE_TEST_MSSQL_DSN")
	if dsn == "" {
		t.Skip("INFRAMOLE_TEST_MSSQL_DSN not set")
	}
	names, err := listDatabases(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		switch n {
		case "master", "model", "msdb", "tempdb":
			t.Fatalf("system database listed: %v", names)
		}
	}
	t.Logf("user databases: %v", names)
	if want := os.Getenv("INFRAMOLE_TEST_MSSQL_EXPECT"); want != "" && (len(names) == 0 || names[0] != want) {
		t.Fatalf("expected %q first, got %v", want, names)
	}
}

// Live check of the database clients query (M42), against the same server:
// a login without VIEW SERVER STATE is refused ("access denied"), and once
// granted it sees another connection's session to a user database.
//
//	INFRAMOLE_TEST_MSSQL_DSN="sqlserver://sa:<pw>@localhost:14333" go test -tags mssqllive -run Clients ./internal/workloads
func TestListClientsLive(t *testing.T) {
	dsn := os.Getenv("INFRAMOLE_TEST_MSSQL_DSN")
	if dsn == "" {
		t.Skip("INFRAMOLE_TEST_MSSQL_DSN not set")
	}
	ctx := context.Background()
	admin, err := sql.Open("sqlserver", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, stmt := range []string{
		`IF DB_ID('M42Billing') IS NULL CREATE DATABASE M42Billing`,
		`IF SUSER_ID('m42agent') IS NULL CREATE LOGIN m42agent WITH PASSWORD = 'M42-Agent-Pass!', CHECK_POLICY = OFF`,
		`REVOKE VIEW SERVER STATE FROM m42agent`,
	} {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	// Another client with a session open to the user database.
	u, _ := url.Parse(dsn)
	q := u.Query()
	q.Set("database", "M42Billing")
	u.RawQuery = q.Encode()
	app, err := sql.Open("sqlserver", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err := app.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	agent := *u
	agent.User = url.UserPassword("m42agent", "M42-Agent-Pass!")
	q.Set("database", "master")
	agent.RawQuery = q.Encode()

	if _, err := listClients(ctx, agent.String()); !errors.Is(err, health.ErrAccessDenied) {
		t.Fatalf("without the permission: want access denied, got %v", err)
	}
	if _, err := admin.ExecContext(ctx, `GRANT VIEW SERVER STATE TO m42agent`); err != nil {
		t.Fatal(err)
	}
	rows, err := listClients(ctx, agent.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rows: %+v", rows)
	clients := toClients("mssql", "MSSQLSERVER", rows)
	t.Logf("clients: %+v", clients)
	found := false
	for _, r := range rows {
		found = found || (r.database == "M42Billing" && r.sessions >= 1 && r.port == 1433)
		if r.database == "master" {
			t.Fatalf("system database listed: %+v", rows)
		}
	}
	if !found {
		t.Fatalf("the session to M42Billing was not listed: %+v", rows)
	}
}
