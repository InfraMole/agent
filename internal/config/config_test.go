// SPDX-License-Identifier: AGPL-3.0-only
package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "depmap", "agent.json")
	want := &File{Server: "https://x", AgentID: "a1", AgentSecret: "dmp_agt_x", ReportIntervalSec: 300, SampleIntervalSec: 30}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("perm %v", info.Mode().Perm())
		}
	}
}

func TestLoadMissingIsNotEnrolled(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("got %v", err)
	}
}
