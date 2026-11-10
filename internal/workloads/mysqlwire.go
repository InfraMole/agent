// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MySQL capability flags used by the agent.
const (
	myLongPassword     = 0x00000001
	myProtocol41       = 0x00000200
	myTransactions     = 0x00002000
	mySecureConnection = 0x00008000
	myPluginAuth       = 0x00080000
)

// mysqlListDatabases speaks the minimum of the MySQL / MariaDB protocol over
// an already-open local socket: log in as `user` with socket authentication
// (auth_socket / unix_socket: the OS user is the credential, no password),
// run SHOW DATABASES, quit. Any password-based method is refused.
func mysqlListDatabases(conn io.ReadWriter, user string) ([]string, error) {
	c, err := mysqlLogin(conn, user)
	if err != nil {
		return nil, err
	}
	defer c.quit()
	rows, err := c.query("SHOW DATABASES")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) > 0 {
			names = append(names, row[0])
		}
	}
	return names, nil
}

// mysqlLogin logs in as `user` with socket authentication only.
func mysqlLogin(conn io.ReadWriter, user string) (*myConn, error) {
	c := &myConn{r: bufio.NewReader(conn), w: conn}

	hs, err := c.read()
	if err != nil {
		return nil, err
	}
	if len(hs) == 0 || hs[0] == 0xff {
		return nil, fmt.Errorf("mysql: %s", myError(hs))
	}
	if hs[0] != 10 {
		return nil, errors.New("mysql: unsupported handshake")
	}
	plugin := myHandshakePlugin(hs)

	// HandshakeResponse41 with an empty auth response.
	resp := make([]byte, 32)
	binary.LittleEndian.PutUint32(resp[0:], myLongPassword|myProtocol41|myTransactions|mySecureConnection|myPluginAuth)
	binary.LittleEndian.PutUint32(resp[4:], 1<<24)
	resp[8] = 45 // utf8mb4_general_ci
	resp = append(resp, user...)
	resp = append(resp, 0, 0) // NUL after the user, then an auth response of length 0
	resp = append(resp, plugin...)
	resp = append(resp, 0)
	if err := c.write(resp); err != nil {
		return nil, err
	}

	for {
		p, err := c.read()
		if err != nil {
			return nil, err
		}
		switch {
		case len(p) > 0 && p[0] == 0x00: // OK: logged in
			return c, nil
		case len(p) > 0 && p[0] == 0xff:
			// "Access denied … (using password: NO)": the account needs a password.
			return nil, fmt.Errorf("%w (mysql: %s)", ErrPasswordRequired, myError(p))
		case len(p) > 0 && p[0] == 0xfe: // AuthSwitchRequest
			name := cString(p[1:])
			if name != "auth_socket" && name != "unix_socket" {
				return nil, ErrPasswordRequired
			}
			if err := c.write(nil); err != nil { // socket auth needs no data
				return nil, err
			}
		default: // AuthMoreData (e.g. caching_sha2_password) = a password method
			return nil, ErrPasswordRequired
		}
	}
}

// myServerError: the server refused a statement; the session is still usable.
type myServerError struct{ msg string }

func (e *myServerError) Error() string { return "mysql: " + e.msg }

// query runs one statement (COM_QUERY, text protocol) and returns its rows
// as text columns, NULL as "".
func (c *myConn) query(sql string) ([][]string, error) {
	c.seq = 0
	if err := c.write(append([]byte{0x03}, sql...)); err != nil {
		return nil, err
	}
	first, err := c.read()
	if err != nil {
		return nil, err
	}
	if len(first) > 0 && first[0] == 0xff {
		return nil, &myServerError{myError(first)}
	}
	cols, _ := lenEncInt(first)
	for i := uint64(0); i < cols; i++ { // column definitions
		if _, err := c.read(); err != nil {
			return nil, err
		}
	}
	if _, err := c.read(); err != nil { // EOF after the definitions
		return nil, err
	}
	var rows [][]string
	for {
		p, err := c.read()
		if err != nil {
			return nil, err
		}
		if len(p) > 0 && p[0] == 0xfe && len(p) < 9 { // EOF: end of rows
			return rows, nil
		}
		if len(p) > 0 && p[0] == 0xff {
			return nil, &myServerError{myError(p)}
		}
		row := make([]string, 0, cols)
		for i := 0; uint64(len(row)) < cols && i < len(p); {
			if p[i] == 0xfb { // NULL
				row = append(row, "")
				i++
				continue
			}
			n, used := lenEncInt(p[i:])
			if used == 0 || i+used+int(n) > len(p) {
				return nil, errors.New("mysql: malformed row")
			}
			row = append(row, string(p[i+used:i+used+int(n)]))
			i += used + int(n)
		}
		rows = append(rows, row)
	}
}

func (c *myConn) quit() {
	c.seq = 0
	_ = c.write([]byte{0x01}) // COM_QUIT
}

type myConn struct {
	r   *bufio.Reader
	w   io.Writer
	seq byte
}

func (c *myConn) read() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	c.seq = hdr[3] + 1
	p := make([]byte, n)
	_, err := io.ReadFull(c.r, p)
	return p, err
}

func (c *myConn) write(p []byte) error {
	hdr := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), c.seq}
	c.seq++
	_, err := c.w.Write(append(hdr, p...))
	return err
}

// myHandshakePlugin extracts the auth plugin name from a v10 handshake.
func myHandshakePlugin(p []byte) string {
	i := 1 + len(cString(p[1:])) + 1 // protocol version + server version
	i += 4 + 8 + 1                   // connection id, auth data part 1, filler
	if i+2 > len(p) {
		return "mysql_native_password"
	}
	caps := uint32(binary.LittleEndian.Uint16(p[i:]))
	i += 2
	if i+5 > len(p) {
		return "mysql_native_password"
	}
	caps |= uint32(binary.LittleEndian.Uint16(p[i+3:])) << 16
	authLen := int(p[i+5])
	i += 1 + 2 + 2 + 1 + 10 // charset, status, caps upper, auth length, reserved
	if caps&mySecureConnection != 0 {
		i += max(13, authLen-8)
	}
	if caps&myPluginAuth != 0 && i < len(p) {
		return cString(p[i:])
	}
	return "mysql_native_password"
}

func myError(p []byte) string {
	if len(p) < 3 {
		return "error"
	}
	msg := p[3:]
	if len(msg) > 0 && msg[0] == '#' && len(msg) >= 6 {
		msg = msg[6:]
	}
	return string(msg)
}

func cString(p []byte) string {
	for i, b := range p {
		if b == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}

// lenEncInt decodes a MySQL length-encoded integer; used = bytes consumed.
func lenEncInt(p []byte) (uint64, int) {
	if len(p) == 0 {
		return 0, 0
	}
	switch b := p[0]; {
	case b < 0xfb:
		return uint64(b), 1
	case b == 0xfc && len(p) >= 3:
		return uint64(binary.LittleEndian.Uint16(p[1:])), 3
	case b == 0xfd && len(p) >= 4:
		return uint64(p[1]) | uint64(p[2])<<8 | uint64(p[3])<<16, 4
	case b == 0xfe && len(p) >= 9:
		return binary.LittleEndian.Uint64(p[1:]), 9
	}
	return 0, 0
}
