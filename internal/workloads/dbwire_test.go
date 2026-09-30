// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
)

// ───────────────────────── PostgreSQL ─────────────────────────

func pgMsg(typ byte, body []byte) []byte {
	out := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(body)))
	return append(out, body...)
}

func pgDataRow(v string) []byte {
	b := []byte{0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[2:], uint32(len(v)))
	return pgMsg('D', append(b, v...))
}

// fakePG plays a server: reads the startup, answers auth (0 = ok), serves the query.
func fakePG(t *testing.T, conn net.Conn, authCode uint32, gotQuery *string) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return
	}
	startup := make([]byte, binary.BigEndian.Uint32(n[:])-4)
	_, _ = io.ReadFull(r, startup)
	if !strings.Contains(string(startup), "user\x00root\x00") {
		t.Errorf("startup without user root: %q", startup)
	}
	code := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(code, authCode)
	_, _ = conn.Write(pgMsg('R', code))
	if authCode != 0 {
		return
	}
	_, _ = conn.Write(append(pgMsg('S', []byte("server_version\x0017.0\x00")), pgMsg('Z', []byte{'I'})...))
	typ, _ := r.ReadByte()
	_, _ = io.ReadFull(r, n[:])
	q := make([]byte, binary.BigEndian.Uint32(n[:])-4)
	_, _ = io.ReadFull(r, q)
	if typ == 'Q' {
		*gotQuery = strings.TrimRight(string(q), "\x00")
	}
	var out []byte
	out = append(out, pgMsg('T', []byte("\x00\x01datname\x00"))...)
	out = append(out, pgDataRow("orders")...)
	out = append(out, pgDataRow("postgres")...)
	out = append(out, pgMsg('C', []byte("SELECT 2\x00"))...)
	out = append(out, pgMsg('Z', []byte{'I'})...)
	_, _ = conn.Write(out)
	_, _ = io.Copy(io.Discard, r) // Terminate
}

func TestPostgresPeerAuth(t *testing.T) {
	client, server := net.Pipe()
	var query string
	go fakePG(t, server, 0, &query)
	names, err := pgListDatabases(client, "root")
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"orders", "postgres"}) {
		t.Fatalf("names = %v", names)
	}
	if query != "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1" {
		t.Fatalf("unexpected query %q", query)
	}
}

func TestPostgresRefusesPasswords(t *testing.T) {
	client, server := net.Pipe()
	var query string
	go fakePG(t, server, 10 /* SASL */, &query)
	_, err := pgListDatabases(client, "root")
	client.Close()
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("want ErrPasswordRequired, got %v", err)
	}
}

// ───────────────────────── MySQL / MariaDB ─────────────────────────

func myPacket(seq byte, p []byte) []byte {
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}, p...)
}

func myHandshake(plugin string) []byte {
	p := []byte{10}
	p = append(p, "11.4.2-MariaDB\x00"...)
	p = append(p, 1, 0, 0, 0)          // connection id
	p = append(p, "abcdefgh"...)       // auth data part 1
	p = append(p, 0)                   // filler
	p = append(p, 0x00, 0xa2)          // caps low: PROTOCOL_41 | SECURE_CONNECTION
	p = append(p, 45, 2, 0)            // charset, status
	p = append(p, 0x08, 0x00)          // caps high: PLUGIN_AUTH
	p = append(p, 21)                  // auth data length
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, "ijklmnopqrst\x00"...)
	return append(p, plugin+"\x00"...)
}

func readPacket(r *bufio.Reader) (byte, []byte) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil
	}
	p := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
	_, _ = io.ReadFull(r, p)
	return h[3], p
}

// fakeMySQL: handshake → (optional AuthSwitch) → OK → SHOW DATABASES.
func fakeMySQL(t *testing.T, conn net.Conn, switchTo string) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	_, _ = conn.Write(myPacket(0, myHandshake("mysql_native_password")))
	seq, resp := readPacket(r)
	if seq != 1 || !strings.HasPrefix(string(resp[32:]), "root\x00") {
		t.Errorf("bad handshake response seq=%d %q", seq, resp)
	}
	next := seq + 1
	if switchTo != "" {
		_, _ = conn.Write(myPacket(next, append([]byte{0xfe}, switchTo+"\x00"...)))
		if switchTo != "unix_socket" {
			return
		}
		seq, _ = readPacket(r) // empty socket-auth answer
		next = seq + 1
	}
	_, _ = conn.Write(myPacket(next, []byte{0, 0, 0, 2, 0, 0, 0}))
	_, q := readPacket(r)
	if string(q) != "\x03SHOW DATABASES" {
		t.Errorf("unexpected command %q", q)
	}
	var out []byte
	out = append(out, myPacket(1, []byte{1})...)                                 // 1 column
	out = append(out, myPacket(2, []byte("\x03def\x00\x00\x00\x08Database"))...) // definition (content ignored)
	out = append(out, myPacket(3, []byte{0xfe, 0, 0, 2, 0})...)                  // EOF
	out = append(out, myPacket(4, append([]byte{9}, "wordpress"...))...)
	out = append(out, myPacket(5, append([]byte{5}, "mysql"...))...)
	out = append(out, myPacket(6, []byte{0xfe, 0, 0, 2, 0})...) // EOF
	_, _ = conn.Write(out)
	_, _ = io.Copy(io.Discard, r)
}

func TestMySQLSocketAuth(t *testing.T) {
	client, server := net.Pipe()
	go fakeMySQL(t, server, "unix_socket")
	names, err := mysqlListDatabases(client, "root")
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(names, []string{"wordpress", "mysql"}) {
		t.Fatalf("names = %v", names)
	}
}

func TestMySQLRefusesPasswordMethods(t *testing.T) {
	client, server := net.Pipe()
	go fakeMySQL(t, server, "caching_sha2_password")
	_, err := mysqlListDatabases(client, "root")
	client.Close()
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("want ErrPasswordRequired, got %v", err)
	}
}

func TestMySQLHandshakePlugin(t *testing.T) {
	if got := myHandshakePlugin(myHandshake("unix_socket")); got != "unix_socket" {
		t.Fatalf("plugin = %q", got)
	}
}
