// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"encoding/json"
	"testing"
)

func TestToClients(t *testing.T) {
	rows := []clientRow{
		{"Billing", "10.0.0.23", 1433, 3},
		{"Billing", "::ffff:10.0.0.23", 1433, 2}, // same client, IPv4-mapped
		{"Billing", "10.0.0.24", 1433, 1},
		{"Customers", "2001:db8::7", 1433, 1},
		{"Billing", "<local machine>", 1433, 5}, // shared memory
		{"Billing", "127.0.0.1", 1433, 1},
		{"Billing", "fe80::1", 1433, 1},
		{"", "10.0.0.25", 1433, 1},
		{"Billing", "10.0.0.26", 0, 1},
	}
	got, _ := json.Marshal(toClients("mssql", "MSSQLSERVER", rows))
	want := `[{"engine":"mssql","instance":"MSSQLSERVER","database":"Billing","address":"10.0.0.23","port":1433,"sessions":5},` +
		`{"engine":"mssql","instance":"MSSQLSERVER","database":"Billing","address":"10.0.0.24","port":1433,"sessions":1},` +
		`{"engine":"mssql","instance":"MSSQLSERVER","database":"Customers","address":"2001:db8::7","port":1433,"sessions":1}]`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if len(toClients("mssql", "X", nil)) != 0 {
		t.Fatal("no rows, no clients")
	}
}
