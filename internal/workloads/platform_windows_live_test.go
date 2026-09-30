// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows && mssqllive

package workloads

import (
	"context"
	"os"
	"testing"
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
