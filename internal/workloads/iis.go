// SPDX-License-Identifier: AGPL-3.0-only
// Package workloads reports what runs on a Windows host (M16): IIS sites and,
// when enabled locally, SQL Server database names. Names and bindings only —
// never paths, application pools, connection strings or credentials.
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
func ParseApplicationHost(r io.Reader) ([]protocol.IISSite, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var (
		path  []string
		sites []protocol.IISSite
		cur   *protocol.IISSite
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
					sites = append(sites, protocol.IISSite{Name: clip(siteName, 256), Bindings: []protocol.IISBinding{}})
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

// parseBinding: bindingInformation is "ip:port:host" ("*:443:portal.corp.local",
// "[::1]:80:"); only http and https are reported.
func parseBinding(proto, info string) (protocol.IISBinding, bool) {
	proto = strings.ToLower(proto)
	if proto != "http" && proto != "https" {
		return protocol.IISBinding{}, false
	}
	last := strings.LastIndex(info, ":")
	if last < 0 {
		return protocol.IISBinding{}, false
	}
	host := info[last+1:]
	rest := info[:last]
	sep := strings.LastIndex(rest, ":")
	if sep < 0 {
		return protocol.IISBinding{}, false
	}
	port, err := strconv.Atoi(rest[sep+1:])
	if err != nil || port < 1 || port > 65535 {
		return protocol.IISBinding{}, false
	}
	return protocol.IISBinding{Protocol: proto, Port: port, Host: clip(strings.ToLower(host), 253)}, true
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
