// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/InfraMole/agent/internal/health"
)

// ErrPasswordRequired: the server wants a password; the agent never has one
// (it only uses peer / socket authentication — no credentials stored).
var ErrPasswordRequired = fmt.Errorf("%w: the server asked for a password; allow the agent's user with peer / socket authentication", health.ErrAccessDenied)

// pgListDatabases speaks the minimum of the PostgreSQL v3 protocol over an
// already-open local socket: startup as `user` (peer authentication), one
// simple query for database names, terminate. Nothing else is ever sent.
func pgListDatabases(conn io.ReadWriter, user string) ([]string, error) {
	results, err := pgQuery(conn, user, "SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY 1")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, row := range results[0] {
		names = append(names, row[0])
	}
	return names, nil
}

// pgQuery logs in as `user` (peer authentication: any password request is
// refused), runs each query in turn with the simple query protocol and
// terminates. One result per query: rows of text columns, NULL as "".
func pgQuery(conn io.ReadWriter, user string, queries ...string) ([][][]string, error) {
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

	results := make([][][]string, 0, len(queries))
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
		case 'Z': // ReadyForQuery: send the next query, or finish
			if len(results) == len(queries) {
				_, _ = w.Write([]byte{'X', 0, 0, 0, 4}) // Terminate
				_ = w.Flush()
				return results, nil
			}
			q := append([]byte(queries[len(results)]), 0)
			hdr := []byte{'Q', 0, 0, 0, 0}
			binary.BigEndian.PutUint32(hdr[1:], uint32(4+len(q)))
			if _, err := w.Write(append(hdr, q...)); err != nil {
				return nil, err
			}
			if err := w.Flush(); err != nil {
				return nil, err
			}
			results = append(results, [][]string{})
		case 'D': // DataRow: int16 columns, then per column int32 length (-1 = NULL) + bytes
			if len(results) == 0 {
				return nil, errors.New("postgres: data before a query")
			}
			row, err := pgParseRow(body)
			if err != nil {
				return nil, err
			}
			results[len(results)-1] = append(results[len(results)-1], row)
		}
		// 'S' ParameterStatus, 'K' BackendKeyData, 'T' RowDescription,
		// 'C' CommandComplete, 'N' NoticeResponse: nothing to do.
	}
}

func pgParseRow(body []byte) ([]string, error) {
	if len(body) < 2 {
		return nil, errors.New("postgres: short data row")
	}
	cols := int(binary.BigEndian.Uint16(body))
	row := make([]string, 0, cols)
	i := 2
	for range cols {
		if i+4 > len(body) {
			return nil, errors.New("postgres: short data row")
		}
		n := int(int32(binary.BigEndian.Uint32(body[i:])))
		i += 4
		if n < 0 {
			row = append(row, "")
			continue
		}
		if i+n > len(body) {
			return nil, errors.New("postgres: short data row")
		}
		row = append(row, string(body[i:i+n]))
		i += n
	}
	return row, nil
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
