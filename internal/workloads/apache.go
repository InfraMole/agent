// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/InfraMole/agent/internal/protocol"
)

// ParseApache reads Apache httpd's configuration from mainPath
// (/etc/apache2/apache2.conf on Debian, /etc/httpd/conf/httpd.conf on RHEL)
// inside fsys (rooted at "/"), following Include / IncludeOptional. Only
// <VirtualHost> blocks and, in them, ServerName, ServerAlias and SSLEngine
// are read — never certificate or key paths, rewrite rules or anything else.
func ParseApache(fsys fs.FS, mainPath string) ([]protocol.WebSite, error) {
	p := &apacheParser{fsys: fsys, root: path.Dir(mainPath), seen: map[string]bool{}}
	if err := p.file(mainPath, 0); err != nil {
		return nil, err
	}
	return mergeSites(p.sites), nil
}

type apacheParser struct {
	fsys  fs.FS
	root  string // ServerRoot: relative includes resolve against it
	seen  map[string]bool
	files int
	sites []*rawSite
	cur   *rawSite
	ports []int // ports of the current <VirtualHost>
	ssl   bool  // SSLEngine on in the current <VirtualHost>
	depth int   // nesting of <VirtualHost> (always 0 or 1)
}

func (p *apacheParser) file(name string, depth int) error {
	if depth > maxIncludeDepth || p.files >= maxConfigFiles || p.seen[name] {
		return nil
	}
	p.seen[name] = true
	p.files++
	data, err := fs.ReadFile(p.fsys, strings.TrimPrefix(name, "/"))
	if err != nil {
		if depth == 0 {
			return err
		}
		return nil
	}
	if len(data) > maxConfigBytes {
		data = data[:maxConfigBytes]
	}
	for _, line := range strings.Split(string(data), "\n") {
		p.line(strings.TrimSpace(line), depth)
	}
	return nil
}

func (p *apacheParser) line(line string, depth int) {
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	fields := strings.Fields(line)
	key := strings.ToLower(fields[0])
	args := fields[1:]
	switch {
	case key == "serverroot" && len(args) > 0 && p.cur == nil:
		p.root = strings.Trim(args[0], `"`)
	case (key == "include" || key == "includeoptional") && len(args) > 0:
		pattern := strings.Trim(args[0], `"`)
		if !path.IsAbs(pattern) {
			pattern = path.Join(p.root, pattern)
		}
		matches, _ := fs.Glob(p.fsys, strings.TrimPrefix(pattern, "/"))
		sort.Strings(matches)
		for _, m := range matches {
			_ = p.file("/"+m, depth+1)
		}
	case strings.HasPrefix(key, "<virtualhost"):
		p.cur = &rawSite{}
		p.ports, p.ssl = nil, false
		// "<VirtualHost *:443 [::]:443>" — the closing ">" may stick to the last address.
		rest := strings.TrimSpace(strings.TrimPrefix(line[len("<VirtualHost"):], ""))
		for _, a := range strings.Fields(strings.TrimSuffix(rest, ">")) {
			p.ports = append(p.ports, apachePort(a))
		}
		if len(p.ports) == 0 {
			p.ports = []int{80}
		}
	case key == "</virtualhost>" && p.cur != nil:
		seen := map[int]bool{}
		for _, port := range p.ports {
			if port < 1 || port > 65535 || seen[port] {
				continue
			}
			seen[port] = true
			proto := "http"
			if p.ssl || port == 443 {
				proto = "https"
			}
			p.cur.bindings = append(p.cur.bindings, protocol.WebBinding{Protocol: proto, Port: port})
		}
		if len(p.cur.bindings) > 0 {
			p.sites = append(p.sites, p.cur)
		}
		p.cur = nil
	case p.cur != nil && key == "servername" && len(args) > 0:
		p.cur.names = append([]string{apacheName(args[0])}, p.cur.names...)
	case p.cur != nil && key == "serveralias":
		for _, a := range args {
			if n := apacheName(a); n != "" && !strings.Contains(n, "*") {
				p.cur.names = append(p.cur.names, n)
			}
		}
	case p.cur != nil && key == "sslengine" && len(args) > 0:
		p.ssl = strings.EqualFold(args[0], "on")
	}
}

// apachePort: "*:443", "_default_:443", "[::]:80", "10.0.0.5:8080", "*" (80).
func apachePort(addr string) int {
	i := strings.LastIndex(addr, ":")
	if i < 0 || strings.HasSuffix(addr, "]") {
		return 80
	}
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return 0
	}
	return port
}

// apacheName: "https://www.example.com:443" → "www.example.com".
func apacheName(s string) string {
	s = strings.ToLower(strings.Trim(s, `"`))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s, "]") {
		s = s[:i]
	}
	return clip(s, 253)
}
