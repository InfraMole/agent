// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package collect

import (
	"context"
	"errors"
	"io/fs"
	"os"
)

// DNSServers lists the resolvers this host is configured to use (M39). With
// systemd-resolved, /etc/resolv.conf points at the local stub (127.0.0.53),
// so the upstream servers are read from /run/systemd/resolve/resolv.conf.
// found is false when the host has no resolver configuration at all.
func DNSServers(_ context.Context) (servers []string, found bool, err error) {
	for _, path := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		f, err := os.Open(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, true, err
		}
		names := parseResolvConf(f)
		f.Close()
		found = true
		if usable := usableResolvers(names); len(usable) > 0 {
			return usable, true, nil
		}
	}
	return []string{}, found, nil
}
