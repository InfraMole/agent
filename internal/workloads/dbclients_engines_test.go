// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/InfraMole/agent/internal/health"
)

// Database clients on Linux (M45): the engine queries against scripted
// servers. The same queries ran against PostgreSQL 17, MySQL 8.4 and
// MariaDB 11 in Docker (granted and not granted) before release.

// answer: rows of a query, or a server error.
type answer struct {
	rows [][]string
	err  string
}

// ───────────────────────── PostgreSQL ─────────────────────────

func pgRow(cols ...string) []byte {
	b := []byte{0, 0}
	binary.BigEndian.PutUint16(b, uint16(len(cols)))
	for _, c := range cols {
		n := []byte{0, 0, 0, 0}
		binary.BigEndian.PutUint32(n, uint32(len(c)))
		b = append(append(b, n...), c...)
	}
	return pgMsg('D', b)
}

// scriptedPG logs the client in (peer) and answers each simple query from the script.
func scriptedPG(t *testing.T, conn net.Conn, script map[string]answer, asked *[]string) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return
	}
	startup := make([]byte, binary.BigEndian.Uint32(n[:])-4)
	_, _ = io.ReadFull(r, startup)
	_, _ = conn.Write(append(pgMsg('R', []byte{0, 0, 0, 0}), pgMsg('Z', []byte{'I'})...))
	for {
		typ, err := r.ReadByte()
		if err != nil || typ == 'X' {
			return
		}
		_, _ = io.ReadFull(r, n[:])
		q := make([]byte, binary.BigEndian.Uint32(n[:])-4)
		_, _ = io.ReadFull(r, q)
		query := strings.TrimRight(string(q), "\x00")
		*asked = append(*asked, query)
		a, ok := script[query]
		if !ok {
			t.Errorf("unexpected query %q", query)
		}
		var out []byte
		if a.err != "" {
			out = append(out, pgMsg('E', []byte("SERROR\x00M"+a.err+"\x00\x00"))...)
		} else {
			for _, row := range a.rows {
				out = append(out, pgRow(row...)...)
			}
			out = append(out, pgMsg('C', []byte("SELECT\x00"))...)
		}
		_, _ = conn.Write(append(out, pgMsg('Z', []byte{'I'})...))
	}
}

func TestPostgresSessionClients(t *testing.T) {
	run := func(granted string) (string, error, []string) {
		client, server := net.Pipe()
		var asked []string
		go scriptedPG(t, server, map[string]answer{
			pgClientsPermission: {rows: [][]string{{granted}}},
			pgClientsQuery: {rows: [][]string{
				{"orders", "10.0.0.21", "3"},
				{"orders", "10.0.0.22", "1"},
				{"postgres", "10.0.0.21", "1"}, // system database
				{"orders", "127.0.0.1", "2"},   // local
			}},
		}, &asked)
		list, err := pgSessionClients(client, "root", 5433)
		client.Close()
		b, _ := json.Marshal(list)
		return string(b), err, asked
	}

	got, err, asked := run("t")
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"engine":"postgresql","instance":"5433","database":"orders","address":"10.0.0.21","port":5433,"sessions":3},` +
		`{"engine":"postgresql","instance":"5433","database":"orders","address":"10.0.0.22","port":5433,"sessions":1}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %q", asked)
	}

	// Without pg_read_all_stats the list would only hide client addresses.
	if _, err, _ := run("f"); !errors.Is(err, health.ErrAccessDenied) {
		t.Fatalf("want access denied, got %v", err)
	}
}

// ───────────────────────── MySQL / MariaDB ─────────────────────────

func myLenEnc(s string) []byte { return append([]byte{byte(len(s))}, s...) }

// scriptedMySQL logs the client in (socket auth) and answers each COM_QUERY.
func scriptedMySQL(t *testing.T, conn net.Conn, script map[string]answer, asked *[]string) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	_, _ = conn.Write(myPacket(0, myHandshake("unix_socket")))
	seq, _ := readPacket(r)
	_, _ = conn.Write(myPacket(seq+1, []byte{0, 0, 0, 2, 0, 0, 0}))
	for {
		_, p := readPacket(r)
		if len(p) == 0 || p[0] == 0x01 { // gone or COM_QUIT
			return
		}
		query := string(p[1:])
		*asked = append(*asked, query)
		a, ok := script[query]
		if !ok {
			t.Errorf("unexpected query %q", query)
		}
		if a.err != "" {
			_, _ = conn.Write(myPacket(1, append([]byte{0xff, 0x8e, 0x04}, "#42000"+a.err...)))
			continue
		}
		cols := 1
		if len(a.rows) > 0 {
			cols = len(a.rows[0])
		}
		var out []byte
		s := byte(1)
		out = append(out, myPacket(s, []byte{byte(cols)})...)
		for range cols {
			s++
			out = append(out, myPacket(s, []byte("\x03def\x00\x00\x00\x01c"))...)
		}
		s++
		out = append(out, myPacket(s, []byte{0xfe, 0, 0, 2, 0})...)
		for _, row := range a.rows {
			var b []byte
			for _, c := range row {
				if c == "NULL" {
					b = append(b, 0xfb)
				} else {
					b = append(b, myLenEnc(c)...)
				}
			}
			s++
			out = append(out, myPacket(s, b)...)
		}
		s++
		out = append(out, myPacket(s, []byte{0xfe, 0, 0, 2, 0})...)
		_, _ = conn.Write(out)
	}
}

func runMySQL(t *testing.T, script map[string]answer) (string, error, []string) {
	client, server := net.Pipe()
	var asked []string
	go scriptedMySQL(t, server, script, &asked)
	list, err := mySessionClients(client, "root")
	client.Close()
	b, _ := json.Marshal(list)
	return string(b), err, asked
}

func TestMySQLSessionClientsFromPerformanceSchema(t *testing.T) {
	got, err, asked := runMySQL(t, map[string]answer{
		mySettings: {rows: [][]string{{"1", "3306"}}},
		myClientsPerfQ: {rows: [][]string{
			{"shop", "::ffff:10.0.0.31", "2"},
			{"mysql", "10.0.0.31", "1"}, // system database
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"engine":"mysql","instance":"default","database":"shop","address":"10.0.0.31","port":3306,"sessions":2}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if len(asked) != 2 {
		t.Fatalf("PROCESSLIST is not needed: asked %q", asked)
	}
}

func TestMySQLSessionClientsFromProcesslist(t *testing.T) {
	list := answer{rows: [][]string{
		{"wiki", "10.0.0.41:51234"},
		{"wiki", "10.0.0.41:51240"},
		{"wiki", "[2001:db8::9]:40000"},
		{"wiki", "app01:51234"}, // a name: never resolved
		{"wiki", "localhost"},
	}}
	// MariaDB's default: performance_schema off.
	got, err, _ := runMySQL(t, map[string]answer{
		mySettings:         {rows: [][]string{{"0", "3307"}}},
		myProcessPrivilege: {rows: [][]string{{"1"}}},
		myClientsListQ:     list,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"engine":"mysql","instance":"default","database":"wiki","address":"10.0.0.41","port":3307,"sessions":2},` +
		`{"engine":"mysql","instance":"default","database":"wiki","address":"2001:db8::9","port":3307,"sessions":1}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}

	// performance_schema on but not readable: falls back to PROCESSLIST.
	got, err, asked := runMySQL(t, map[string]answer{
		mySettings:         {rows: [][]string{{"1", "3307"}}},
		myClientsPerfQ:     {err: "SELECT command denied to user 'root'@'localhost' for table 'threads'"},
		myProcessPrivilege: {rows: [][]string{{"1"}}},
		myClientsListQ:     list,
	})
	if err != nil || got != want || len(asked) != 4 {
		t.Fatalf("fallback: err=%v got=%s asked=%q", err, got, asked)
	}

	// Neither readable: refused, never an empty list.
	_, err, _ = runMySQL(t, map[string]answer{
		mySettings:         {rows: [][]string{{"1", "3306"}}},
		myClientsPerfQ:     {err: "SELECT command denied"},
		myProcessPrivilege: {rows: [][]string{{"0"}}},
	})
	if !errors.Is(err, health.ErrAccessDenied) {
		t.Fatalf("want access denied, got %v", err)
	}
}

func TestProcesslistAddress(t *testing.T) {
	for host, want := range map[string]string{
		"10.0.0.5:51234":        "10.0.0.5",
		"[2001:db8::5]:51234":   "2001:db8::5",
		"::ffff:10.0.0.5:51234": "::ffff:10.0.0.5",
		"app01:51234":           "",
		"localhost":             "",
		"":                      "",
	} {
		got, ok := processlistAddress(host)
		if got != want || ok != (want != "") {
			t.Errorf("%q → %q %v, want %q", host, got, ok, want)
		}
	}
}
