// SPDX-License-Identifier: AGPL-3.0-only
// Package health turns collector failures into report issues (M39): the
// server learns which collector failed and a category — never the error
// text, which can carry paths, host names or user names.
package health

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"sort"
	"sync"

	"github.com/InfraMole/agent/internal/protocol"
)

// ErrAccessDenied marks a failure caused by missing rights or a rejected
// credential, so it is reported as "access-denied". Wrap it with %w.
var ErrAccessDenied = errors.New("access denied")

// Classify maps an error to an issue category.
func Classify(err error) string {
	var netErr net.Error
	var opErr *net.OpError
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, ErrAccessDenied), errors.Is(err, fs.ErrPermission):
		return protocol.IssueAccessDenied
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return protocol.IssueTimeout
	case errors.As(err, &dnsErr), errors.As(err, &opErr):
		return protocol.IssueUnreachable
	default:
		return protocol.IssueFailed
	}
}

// Set holds the current issue of each collector. Safe for concurrent use;
// the zero value is ready.
type Set struct {
	mu sync.Mutex
	m  map[string]string
}

// Record stores the outcome of one collection: an error sets the
// collector's issue, nil clears it.
func (s *Set) Record(collector string, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.m, collector)
		return
	}
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[collector] = Classify(err)
}

// List returns the current issues sorted by collector (nil when none).
func (s *Set) List() []protocol.Issue {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.Issue
	for c, e := range s.m {
		out = append(out, protocol.Issue{Collector: c, Error: e})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Collector < out[j].Collector })
	return out
}

// Merge combines issue lists, sorted by collector (nil when none).
func Merge(lists ...[]protocol.Issue) []protocol.Issue {
	var out []protocol.Issue
	for _, l := range lists {
		out = append(out, l...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Collector < out[j].Collector })
	return out
}
