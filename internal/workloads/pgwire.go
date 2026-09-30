// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrPasswordRequired: the server wants a password; the agent never has one
// (it only uses peer / socket authentication — no credentials stored).
var ErrPasswordRequired = errors.New("the server asked for a password; allow the agent's user with peer / socket authentication")

// pgListDatabases speaks the minimum of the PostgreSQL v3 protocol over an
// already-open local socket: startup as `user` (peer authentication), one
// simple query for database names, terminate. Nothing else is ever sent.
func pgListDatabases(conn io.ReadWriter, user string) ([]string, error) {
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	// StartupMessage (no type byte): length, protocol 3.0, key/value pairs.
	var params []byte
	for _, kv := range [][2]string{{"user", user}, {"database", "postgres"}, {"application_name", "inframole-agent"}} {
		params = append(params, kv[0]...)
		params = append(params, 0)
		params = append(params, kv[1]...)
		params = append(params, 0)
	}
	params = append(params, 0)
	msg := make([]byte, 8, 8+len(params))
	binary.BigEndian.PutUint32(msg[0:], uint32(8+len(params)))
	binary.BigEndian.PutUint32(msg[4:], 196608)
	if _, err := w.Write(append(msg, params...)); err != nil {
		return nil, err
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}

	const query = "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1"
	sent := false
	var names []string
	for {
		typ, body, err := pgRead(r)
		if err != nil {
			return nil, err
		}
		switch typ {
		case 'R': // Authentication*
			if len(body) < 4 {
				return nil, errors.New("postgres: short authentication message")
			}
			if code := binary.BigEndian.Uint32(body); code != 0 {
				return nil, ErrPasswordRequired
			}
		case 'E':
			return nil, fmt.Errorf("postgres: %s", pgError(body))
		case 'Z': // ReadyForQuery
			if sent {
				_, _ = w.Write([]byte{'X', 0, 0, 0, 4}) // Terminate
				_ = w.Flush()
				return names, nil
			}
			q := append([]byte(query), 0)
			hdr := []byte{'Q', 0, 0, 0, 0}
			binary.BigEndian.PutUint32(hdr[1:], uint32(4+len(q)))
			if _, err := w.Write(append(hdr, q...)); err != nil {
				return nil, err
			}
			if err := w.Flush(); err != nil {
				return nil, err
			}
			sent = true
		case 'D': // DataRow: int16 columns, then int32 length + bytes
			if len(body) < 6 {
				return nil, errors.New("postgres: short data row")
			}
			n := int(int32(binary.BigEndian.Uint32(body[2:])))
			if n >= 0 && 6+n <= len(body) {
				names = append(names, string(body[6:6+n]))
			}
		}
		// 'S' ParameterStatus, 'K' BackendKeyData, 'T' RowDescription,
		// 'C' CommandComplete, 'N' NoticeResponse: nothing to do.
	}
}

func pgRead(r *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if n < 0 || n > 1<<20 {
		return 0, nil, errors.New("postgres: invalid message length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

// pgError returns the 'M' (message) field of an ErrorResponse.
func pgError(body []byte) string {
	for _, field := range strings.Split(string(body), "\x00") {
		if strings.HasPrefix(field, "M") {
			return field[1:]
		}
	}
	return "error"
}
