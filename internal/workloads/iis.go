// SPDX-License-Identifier: AGPL-3.0-only
// Package workloads reports what runs on a Windows host (M16): IIS sites and,
// when enabled locally, SQL Server database names. Names and bindings only —
// never paths, connection strings or credentials. Application pool names
// are read only to tell which site a worker process serves (M42) and never
// leave the host.
package workloads

import (
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/InfraMole/agent/internal/protocol"
)

// ParseApplicationHost reads the <sites> section of IIS's
// applicationHost.config. Only the site name and the http/https bindings
// are kept: every other element and attribute (physicalPath, userName,
// password, applicationPool, …) is skipped without being decoded.
func ParseApplicationHost(r io.Reader) ([]protocol.WebSite, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var (
		path  []string
		sites []protocol.WebSite
		cur   *protocol.WebSite
	)
	inSites := func() bool {
		n := len(path)
		return n >= 3 && path[n-3] == "configuration" && path[n-2] == "system.applicationHost" && path[n-1] == "sites"
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			switch {
			case name == "site" && inSites():
				if siteName := attr(t, "name"); siteName != "" && len(sites) < protocol.MaxIISSites {
					sites = append(sites, protocol.WebSite{Name: clip(siteName, 256), Bindings: []protocol.WebBinding{}})
					cur = &sites[len(sites)-1]
				} else {
					cur = nil
				}
			case name == "binding" && cur != nil && len(path) >= 2 && path[len(path)-1] == "bindings" && path[len(path)-2] == "site":
				if b, ok := parseBinding(attr(t, "protocol"), attr(t, "bindingInformation")); ok &&
					len(cur.Bindings) < protocol.MaxBindingsPerSite {
					cur.Bindings = append(cur.Bindings, b)
				}
			}
			path = append(path, name)
		case xml.EndElement:
			if len(path) > 0 {
				if path[len(path)-1] == "site" {
					cur = nil
				}
				path = path[:len(path)-1]
			}
		}
	}
	return sites, nil
}

// ParsePoolSites maps each application pool (lower-cased) to the sites
// whose applications run in it, from the same <sites> section (M42). An
// application without its own pool uses its site's <applicationDefaults>,
// else the one of <sites>, else IIS's DefaultAppPool. Nothing but site
// names, application pools and the defaults is decoded.
func ParsePoolSites(r io.Reader) (map[string][]string, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	type site struct {
		name, defaultPool string
		pools             []string
		inherits          bool // an application without its own pool
	}
	var (
		path        []string
		sites       []*site
		cur         *site
		globalPool  string
		inSitesPath = func() bool {
			n := len(path)
			return n >= 3 && path[n-3] == "configuration" && path[n-2] == "system.applicationHost" && path[n-1] == "sites"
		}
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			switch {
			case name == "site" && inSitesPath():
				cur = nil
				if n := attr(t, "name"); n != "" {
					cur = &site{name: clip(n, 256)}
					sites = append(sites, cur)
				}
			case name == "applicationDefaults" && inSitesPath():
				globalPool = attr(t, "applicationPool")
			case name == "applicationDefaults" && cur != nil && path[len(path)-1] == "site":
				cur.defaultPool = attr(t, "applicationPool")
			case name == "application" && cur != nil && path[len(path)-1] == "site":
				if pool := attr(t, "applicationPool"); pool != "" {
					cur.pools = append(cur.pools, pool)
				} else {
					cur.inherits = true
				}
			}
			path = append(path, name)
		case xml.EndElement:
			if len(path) > 0 {
				if path[len(path)-1] == "site" {
					cur = nil
				}
				path = path[:len(path)-1]
			}
		}
	}
	if globalPool == "" {
		globalPool = "DefaultAppPool"
	}
	out := map[string][]string{}
	for _, s := range sites {
		pools := s.pools
		if s.inherits {
			if s.defaultPool != "" {
				pools = append(pools, s.defaultPool)
			} else {
				pools = append(pools, globalPool)
			}
		}
		seen := map[string]bool{}
		for _, p := range pools {
			key := strings.ToLower(p)
			if !seen[key] {
				seen[key] = true
				out[key] = append(out[key], s.name)
			}
		}
	}
	return out, nil
}

// ParseWorkerProcesses reads `appcmd list wp /xml` (M42): worker process
// id → application pool. The plain-text form (`WP "1234"
// (applicationPool:Pool)`) is accepted too.
func ParseWorkerProcesses(out []byte) map[int32]string {
	workers := map[int32]string{}
	var doc struct {
		WPs []struct {
			PID  string `xml:"WP.NAME,attr"`
			Pool string `xml:"APPPOOL.NAME,attr"`
		} `xml:"WP"`
	}
	if err := xml.Unmarshal(out, &doc); err == nil {
		for _, wp := range doc.WPs {
			if pid, err := strconv.ParseInt(wp.PID, 10, 32); err == nil && wp.Pool != "" {
				workers[int32(pid)] = wp.Pool
			}
		}
		return workers
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, `WP "`)
		if !ok {
			continue
		}
		id, rest, ok := strings.Cut(rest, `"`)
		_, pool, found := strings.Cut(rest, "(applicationPool:")
		pool, _, closed := strings.Cut(pool, ")")
		if pid, err := strconv.ParseInt(id, 10, 32); ok && found && closed && err == nil && pool != "" {
			workers[int32(pid)] = pool
		}
	}
	return workers
}

// SiteOfPool: the one site served by a pool, "" when none or several.
func SiteOfPool(poolSites map[string][]string, pool string) string {
	if sites := poolSites[strings.ToLower(pool)]; len(sites) == 1 {
		return sites[0]
	}
	return ""
}

// parseBinding: bindingInformation is "ip:port:host" ("*:443:portal.corp.local",
// "[::1]:80:"); only http and https are reported.
func parseBinding(proto, info string) (protocol.WebBinding, bool) {
	proto = strings.ToLower(proto)
	if proto != "http" && proto != "https" {
		return protocol.WebBinding{}, false
	}
	last := strings.LastIndex(info, ":")
	if last < 0 {
		return protocol.WebBinding{}, false
	}
	host := info[last+1:]
	rest := info[:last]
	sep := strings.LastIndex(rest, ":")
	if sep < 0 {
		return protocol.WebBinding{}, false
	}
	port, err := strconv.Atoi(rest[sep+1:])
	if err != nil || port < 1 || port > 65535 {
		return protocol.WebBinding{}, false
	}
	return protocol.WebBinding{Protocol: proto, Port: port, Host: clip(strings.ToLower(host), 253)}, true
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func clip(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
