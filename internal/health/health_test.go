// SPDX-License-Identifier: AGPL-3.0-only
package health

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/InfraMole/agent/internal/protocol"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("proxmox: %w: 401", ErrAccessDenied), protocol.IssueAccessDenied},
		{&fs.PathError{Op: "open", Path: "/etc/x", Err: os.ErrPermission}, protocol.IssueAccessDenied},
		{fmt.Errorf("vcenter: %w", context.DeadlineExceeded), protocol.IssueTimeout},
		{&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, protocol.IssueUnreachable},
		{&net.DNSError{Err: "no such host", Name: "pve.local"}, protocol.IssueUnreachable},
		{errors.New("parse applicationHost.config: bad XML"), protocol.IssueFailed},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestSetRecordsAndClears(t *testing.T) {
	var s Set
	if s.List() != nil {
		t.Fatal("empty set must list nil (the field is omitted)")
	}
	s.Record(protocol.CollectorServices, os.ErrPermission)
	s.Record(protocol.CollectorDocker, errors.New("boom"))
	s.Record(protocol.CollectorNginx, nil) // success: nothing to clear
	want := []protocol.Issue{
		{Collector: "docker", Error: protocol.IssueFailed},
		{Collector: "services", Error: protocol.IssueAccessDenied},
	}
	if got := s.List(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	s.Record(protocol.CollectorDocker, nil)
	if got := s.List(); len(got) != 1 || got[0].Collector != "services" {
		t.Fatalf("docker should be cleared, got %v", got)
	}
	var nilSet *Set
	nilSet.Record("x", errors.New("y")) // nil-safe
	if nilSet.List() != nil {
		t.Fatal("nil set lists nil")
	}
}

func TestMergeSorts(t *testing.T) {
	got := Merge([]protocol.Issue{{Collector: "sockets", Error: "failed"}}, nil, []protocol.Issue{{Collector: "docker", Error: "timeout"}})
	if len(got) != 2 || got[0].Collector != "docker" {
		t.Fatalf("got %v", got)
	}
	if Merge(nil, nil) != nil {
		t.Fatal("no issues → nil")
	}
}
