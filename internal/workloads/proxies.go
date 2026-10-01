// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"bufio"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"net"
	"strconv"
	"strings"

	"github.com/InfraMole/agent/internal/protocol"
)

// Reverse-proxy targets (M25): where a site forwards requests, as
// host:port. Paths, query strings, headers and credentials in URLs are
// never kept.

// parseUpstream reads "http://10.0.0.5:8080/app", "https://api.corp.local",
// "127.0.0.1:9000", "backend:8080" or "[::1]:3000". Unix sockets, nginx
// variables and empty targets are skipped.
func parseUpstream(target string) (protocol.Upstream, bool) {
	t := strings.Trim(strings.TrimSpace(target), `"'`)
	if t == "" {
		return protocol.Upstream{}, false
	}
	port := 0
	if i := strings.Index(t, "://"); i >= 0 {
		switch strings.ToLower(t[:i]) {
		case "http", "ws", "grpc", "h2c", "fcgi", "ajp":
			port = 80
		case "https", "wss", "grpcs":
			port = 443
		default:
			return protocol.Upstream{}, false // balancer://, unix://… are handled elsewhere
		}
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:] // never keep user:password@
	}
	// Variables or back-references in the host part make the target unknowable;
	// in the path ("$1", "{R:1}") they were cut above.
	if t == "" || strings.ContainsAny(t, "${}") || strings.HasPrefix(t, "unix:") {
		return protocol.Upstream{}, false
	}
	host := t
	if h, p, err := net.SplitHostPort(t); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || port < 1 || port > 65535 || len(host) > 253 || strings.ContainsAny(host, " \t*") {
		return protocol.Upstream{}, false
	}
	return protocol.Upstream{Host: host, Port: port}, true
}

// addUpstreams appends without duplicates, up to the protocol limit.
func addUpstreams(list []protocol.Upstream, more ...protocol.Upstream) []protocol.Upstream {
	for _, u := range more {
		dup := false
		for _, x := range list {
			if x == u {
				dup = true
				break
			}
		}
		if !dup && len(list) < protocol.MaxUpstreams {
			list = append(list, u)
		}
	}
	return list
}

// ───────────────────────── HAProxy ─────────────────────────

// ParseHAProxy reads haproxy.cfg: each frontend / listen section becomes a
// site (its bind ports) whose upstreams are the servers of the backends it
// uses. Only bind, default_backend, use_backend and server lines are read —
// never certificates, stats credentials or ACL contents.
func ParseHAProxy(fsys fs.FS, mainPath string) ([]protocol.WebSite, error) {
	data, err := fs.ReadFile(fsys, strings.TrimPrefix(mainPath, "/"))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		data = data[:maxConfigBytes]
	}
	type section struct {
		kind, name string
		bindings   []protocol.WebBinding
		backends   []string
		servers    []protocol.Upstream
	}
	var sections []*section
	var cur *section
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), maxConfigBytes)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "global", "defaults", "frontend", "backend", "listen", "resolvers", "peers", "userlist", "program", "http-errors", "cache", "ring", "mailers":
			cur = &section{kind: f[0]}
			if len(f) > 1 {
				cur.name = f[1]
			}
			sections = append(sections, cur)
			continue
		}
		if cur == nil {
			continue
		}
		switch f[0] {
		case "bind":
			if cur.kind == "frontend" || cur.kind == "listen" {
				cur.bindings = append(cur.bindings, haproxyBind(f[1:])...)
			}
		case "default_backend":
			if len(f) > 1 {
				cur.backends = append(cur.backends, f[1])
			}
		case "use_backend":
			if len(f) > 1 {
				cur.backends = append(cur.backends, f[1])
			}
		case "server":
			if (cur.kind == "backend" || cur.kind == "listen") && len(f) > 2 {
				if u, ok := parseUpstream(f[2]); ok {
					cur.servers = append(cur.servers, u)
				}
			}
		}
	}
	backends := map[string][]protocol.Upstream{}
	for _, s := range sections {
		if s.kind == "backend" {
			backends[s.name] = s.servers
		}
	}
	var out []protocol.WebSite
	for _, s := range sections {
		if (s.kind != "frontend" && s.kind != "listen") || len(s.bindings) == 0 || len(out) == protocol.MaxIISSites {
			continue
		}
		site := protocol.WebSite{Name: clip(s.name, 256), Bindings: s.bindings}
		if len(site.Bindings) > protocol.MaxBindingsPerSite {
			site.Bindings = site.Bindings[:protocol.MaxBindingsPerSite]
		}
		site.Upstreams = addUpstreams(nil, s.servers...)
		for _, b := range s.backends {
			site.Upstreams = addUpstreams(site.Upstreams, backends[b]...)
		}
		out = append(out, site)
	}
	return out, nil
}

// haproxyBind: "*:443 ssl crt /etc/…", ":80", "10.0.0.1:80,10.0.0.2:80", "ipv4@:8080".
func haproxyBind(args []string) []protocol.WebBinding {
	if len(args) == 0 {
		return nil
	}
	proto := "http"
	for _, a := range args[1:] {
		if a == "ssl" {
			proto = "https"
		}
	}
	var out []protocol.WebBinding
	for _, addr := range strings.Split(args[0], ",") {
		if i := strings.Index(addr, "@"); i >= 0 {
			if strings.HasPrefix(addr, "unix@") || strings.HasPrefix(addr, "abns@") || strings.HasPrefix(addr, "fd@") {
				continue
			}
			addr = addr[i+1:]
		}
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(strings.SplitN(addr[i+1:], "-", 2)[0]) // "8000-8010": first port
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		out = append(out, protocol.WebBinding{Protocol: proto, Port: port})
	}
	return out
}

// ───────────────────────── IIS (ARR / URL Rewrite) ─────────────────────────

// iisProxyConf: what applicationHost.config says about reverse proxying.
type iisProxyConf struct {
	global []string                       // rewrite URLs of server-wide rules (apply to every site)
	bySite map[string][]string            // <location path="Site"> rewrite URLs
	farms  map[string][]protocol.Upstream // ARR web farms
	roots  map[string]string              // site → physical path of "/" (to read its web.config)
}

// parseIISProxies reads, from applicationHost.config, only rewrite actions
// of type Rewrite (proxying through ARR), web farm servers and each site's
// root folder. Nothing else is decoded, and no path ever leaves the agent.
func parseIISProxies(r io.Reader) (iisProxyConf, error) {
	conf := iisProxyConf{bySite: map[string][]string{}, farms: map[string][]protocol.Upstream{}, roots: map[string]string{}}
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var path []string
	location, site, farm := "", "", ""
	var farmServer string
	app := ""
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return conf, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			parent := ""
			if len(path) > 0 {
				parent = path[len(path)-1]
			}
			switch {
			case name == "location":
				location = attr(t, "path")
			case name == "site" && parent == "sites":
				site = attr(t, "name")
			case name == "application" && site != "":
				app = attr(t, "path")
			case name == "virtualDirectory" && site != "" && app == "/" && attr(t, "path") == "/":
				conf.roots[site] = attr(t, "physicalPath")
			case name == "webFarm":
				farm = attr(t, "name")
			case name == "server" && farm != "" && parent == "webFarm":
				farmServer = attr(t, "address")
			case name == "applicationRequestRouting" && farmServer != "":
				port := 80
				if p, err := strconv.Atoi(attr(t, "httpPort")); err == nil {
					port = p
				}
				if u, ok := parseUpstream(net.JoinHostPort(farmServer, strconv.Itoa(port))); ok {
					conf.farms[strings.ToLower(farm)] = append(conf.farms[strings.ToLower(farm)], u)
				}
				farmServer = ""
			case name == "action" && strings.EqualFold(attr(t, "type"), "Rewrite") && inRewriteRule(path):
				url := attr(t, "url")
				switch {
				case location != "":
					conf.bySite[strings.Split(location, "/")[0]] = append(conf.bySite[strings.Split(location, "/")[0]], url)
				case contains(path, "globalRules") || contains(path, "rules"):
					conf.global = append(conf.global, url)
				}
			}
			path = append(path, name)
		case xml.EndElement:
			if len(path) == 0 {
				continue
			}
			switch path[len(path)-1] {
			case "location":
				location = ""
			case "site":
				site, app = "", ""
			case "application":
				app = ""
			case "webFarm":
				farm = ""
			case "server":
				if farmServer != "" { // a server without ARR settings: default port
					if u, ok := parseUpstream(net.JoinHostPort(farmServer, "80")); ok && farm != "" {
						conf.farms[strings.ToLower(farm)] = append(conf.farms[strings.ToLower(farm)], u)
					}
					farmServer = ""
				}
			}
			path = path[:len(path)-1]
		}
	}
	return conf, nil
}

// webConfigRewrites reads only rewrite rule actions of type Rewrite from a
// site's web.config (connection strings, app settings… are never decoded).
func webConfigRewrites(r io.Reader) []string {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var path []string
	var urls []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return urls
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "action" && strings.EqualFold(attr(t, "type"), "Rewrite") && inRewriteRule(path) {
				urls = append(urls, attr(t, "url"))
			}
			path = append(path, t.Name.Local)
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		}
	}
}

func inRewriteRule(path []string) bool {
	return len(path) >= 2 && path[len(path)-1] == "rule" && contains(path, "rewrite")
}

func contains(path []string, name string) bool {
	for _, p := range path {
		if p == name {
			return true
		}
	}
	return false
}

// iisUpstreams turns rewrite URLs into upstreams: "http://farmName/{R:1}"
// → the farm's servers; "http://10.0.0.5:8080/{R:1}" → that host. Relative
// rewrites (same site) are not proxying and are skipped.
func iisUpstreams(urls []string, farms map[string][]protocol.Upstream) []protocol.Upstream {
	var out []protocol.Upstream
	for _, raw := range urls {
		lower := strings.ToLower(raw)
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			continue
		}
		hostPart := lower[strings.Index(lower, "://")+3:]
		if i := strings.IndexAny(hostPart, "/:?{"); i >= 0 {
			hostPart = hostPart[:i]
		}
		if servers, ok := farms[hostPart]; ok {
			out = addUpstreams(out, servers...)
			continue
		}
		// "{R:1}"-style back-references after the host are fine; in the host they make it unknowable.
		if strings.Contains(hostPart, "{") || hostPart == "" {
			continue
		}
		if u, ok := parseUpstream(regexpBraces(raw)); ok {
			out = addUpstreams(out, u)
		}
	}
	return out
}

// regexpBraces drops "{…}" back-references so the URL parses.
func regexpBraces(s string) string {
	var b strings.Builder
	depth := 0
	for _, c := range s {
		switch {
		case c == '{':
			depth++
		case c == '}' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(c)
		}
	}
	return b.String()
}
