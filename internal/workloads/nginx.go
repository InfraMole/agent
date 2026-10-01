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

// Limits that keep a hostile or looping configuration harmless.
const (
	maxConfigFiles  = 200
	maxIncludeDepth = 10
	maxConfigBytes  = 2 << 20
)

// ParseNginx reads nginx's configuration starting at mainPath (e.g.
// /etc/nginx/nginx.conf) inside fsys (rooted at "/"), following include
// directives. Only `server` blocks of the http context are read, and in them
// only `listen`, `server_name` and the targets of `*_pass` directives (M25;
// host and port only), plus the `server` lines of `upstream` blocks they
// name: certificates, keys, headers and everything else are skipped.
func ParseNginx(fsys fs.FS, mainPath string) ([]protocol.WebSite, error) {
	p := &nginxParser{fsys: fsys, prefix: path.Dir(mainPath), seen: map[string]bool{}, upstreams: map[string][]protocol.Upstream{}}
	if err := p.file(mainPath, nil, 0); err != nil {
		return nil, err
	}
	for _, s := range p.sites {
		for _, pass := range s.passes {
			name := strings.TrimPrefix(strings.TrimPrefix(pass, "http://"), "https://")
			if i := strings.IndexAny(name, "/:"); i >= 0 {
				name = name[:i]
			}
			if servers, ok := p.upstreams[name]; ok {
				s.upstreams = addUpstreams(s.upstreams, servers...)
			} else if u, ok := parseUpstream(pass); ok {
				s.upstreams = addUpstreams(s.upstreams, u)
			}
		}
	}
	return mergeSites(p.sites), nil
}

type nginxParser struct {
	fsys      fs.FS
	prefix    string
	seen      map[string]bool
	files     int
	sites     []*rawSite
	upstreams map[string][]protocol.Upstream // upstream blocks by name
}

// rawSite is one server block / virtual host before merging by name.
type rawSite struct {
	names     []string
	bindings  []protocol.WebBinding
	listened  bool     // a listen directive was seen (even one we skip, like unix:)
	passes    []string // raw *_pass targets (resolved against upstream blocks at the end)
	upstreams []protocol.Upstream
}

type nginxFrame struct {
	name     string
	server   *rawSite
	upstream string // name of an `upstream` block
}

func (p *nginxParser) file(name string, stack []nginxFrame, depth int) error {
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
		return nil // a missing include is not fatal (nginx would refuse to start, we just skip)
	}
	if len(data) > maxConfigBytes {
		data = data[:maxConfigBytes]
	}
	_, err = p.block(tokenizeNginx(string(data)), 0, stack, depth)
	return err
}

// block consumes tokens until the matching "}" and returns the next index.
func (p *nginxParser) block(toks []string, i int, stack []nginxFrame, depth int) (int, error) {
	for i < len(toks) {
		if toks[i] == "}" {
			return i + 1, nil
		}
		// Directive: words up to ";" or "{".
		j := i
		for j < len(toks) && toks[j] != ";" && toks[j] != "{" && toks[j] != "}" {
			j++
		}
		words := toks[i:j]
		if j < len(toks) && toks[j] == "{" {
			frame := nginxFrame{}
			if len(words) > 0 {
				frame.name = words[0]
			}
			if frame.name == "server" && inHTTP(stack) {
				frame.server = &rawSite{}
				p.sites = append(p.sites, frame.server)
			}
			if frame.name == "upstream" && len(words) > 1 {
				frame.upstream = words[1]
			}
			next, err := p.block(toks, j+1, append(stack, frame), depth)
			if err != nil {
				return 0, err
			}
			if frame.server != nil && !frame.server.listened {
				// nginx's default when a server block has no listen at all.
				frame.server.bindings = []protocol.WebBinding{{Protocol: "http", Port: 80}}
			}
			i = next
			continue
		}
		if len(words) > 0 {
			p.directive(words, stack, depth)
		}
		i = j + 1
	}
	return i, nil
}

func inHTTP(stack []nginxFrame) bool {
	for _, f := range stack {
		if f.name == "http" {
			return true
		}
	}
	// Files included from inside http{} (conf.d/*.conf, sites-enabled/*)
	// start without the http frame when parsed standalone; treat a server
	// block outside stream{} / mail{} as http.
	for _, f := range stack {
		if f.name == "stream" || f.name == "mail" {
			return false
		}
	}
	return true
}

func (p *nginxParser) directive(words []string, stack []nginxFrame, depth int) {
	var server *rawSite
	if n := len(stack); n > 0 {
		server = stack[n-1].server
	}
	// *_pass directives live in location blocks: the nearest server counts.
	var enclosing *rawSite
	for i := len(stack) - 1; i >= 0 && enclosing == nil; i-- {
		enclosing = stack[i].server
	}
	switch words[0] {
	case "proxy_pass", "grpc_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass":
		if enclosing != nil && len(words) > 1 && len(enclosing.passes) < 64 {
			enclosing.passes = append(enclosing.passes, words[1])
		}
	case "server":
		if n := len(stack); n > 0 && stack[n-1].upstream != "" && len(words) > 1 {
			if u, ok := parseUpstream(words[1]); ok {
				name := stack[n-1].upstream
				p.upstreams[name] = addUpstreams(p.upstreams[name], u)
			} else if !strings.Contains(words[1], ":") && !strings.HasPrefix(words[1], "unix:") {
				if u, ok := parseUpstream(words[1] + ":80"); ok { // "server app.lan;" = port 80
					name := stack[n-1].upstream
					p.upstreams[name] = addUpstreams(p.upstreams[name], u)
				}
			}
		}
	case "include":
		if len(words) < 2 {
			return
		}
		pattern := words[1]
		if !path.IsAbs(pattern) {
			pattern = path.Join(p.prefix, pattern)
		}
		matches, _ := fs.Glob(p.fsys, strings.TrimPrefix(pattern, "/"))
		sort.Strings(matches)
		for _, m := range matches {
			_ = p.file("/"+m, stack, depth+1)
		}
	case "listen":
		if server == nil || len(words) < 2 {
			return
		}
		server.listened = true
		if b, ok := nginxListen(words[1:]); ok {
			server.bindings = append(server.bindings, b)
		}
	case "server_name":
		if server == nil {
			return
		}
		for _, n := range words[1:] {
			n = strings.ToLower(strings.Trim(n, `"'`))
			if n == "" || n == "_" || strings.HasPrefix(n, "~") || strings.ContainsAny(n, "*$") {
				continue
			}
			server.names = append(server.names, clip(n, 253))
		}
	}
}

// nginxListen: "80", "443 ssl http2", "[::]:443 ssl", "127.0.0.1:8080",
// "localhost" (port 80); unix sockets are skipped.
func nginxListen(args []string) (protocol.WebBinding, bool) {
	addr := args[0]
	if strings.HasPrefix(addr, "unix:") {
		return protocol.WebBinding{}, false
	}
	port := 80
	switch {
	case isDigits(addr):
		port, _ = strconv.Atoi(addr)
	case strings.HasPrefix(addr, "["):
		if i := strings.LastIndex(addr, "]:"); i >= 0 {
			port, _ = strconv.Atoi(addr[i+2:])
		}
	case strings.Contains(addr, ":"):
		port, _ = strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
	}
	if port < 1 || port > 65535 {
		return protocol.WebBinding{}, false
	}
	proto := "http"
	for _, a := range args[1:] {
		if a == "ssl" || a == "quic" {
			proto = "https"
		}
	}
	return protocol.WebBinding{Protocol: proto, Port: port}, true
}

// tokenizeNginx splits a config into words, quoted strings and the
// punctuation "{", "}" and ";"; comments are dropped.
func tokenizeNginx(src string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '#':
			flush()
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			flush()
			q := c
			i++
			for i < len(src) && src[i] != q {
				if src[i] == '\\' && i+1 < len(src) {
					i++
				}
				cur.WriteByte(src[i])
				i++
			}
			toks = append(toks, cur.String())
			cur.Reset()
		case c == '{' || c == '}' || c == ';':
			flush()
			toks = append(toks, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks
}

// mergeSites groups server blocks / virtual hosts by their primary name
// (the usual "port 80 redirects, port 443 serves" pair becomes one site)
// and gives each binding that name as host.
func mergeSites(raw []*rawSite) []protocol.WebSite {
	type acc struct {
		site protocol.WebSite
		seen map[string]bool
	}
	var order []string
	byName := map[string]*acc{}
	for _, r := range raw {
		if len(r.bindings) == 0 {
			continue // only unix sockets: not reachable over TCP
		}
		name, host := "", ""
		if len(r.names) > 0 {
			name, host = r.names[0], r.names[0]
		} else {
			ports := make([]string, 0, len(r.bindings))
			for _, b := range r.bindings {
				ports = append(ports, strconv.Itoa(b.Port))
			}
			name = "default (port " + strings.Join(ports, ", ") + ")"
		}
		a := byName[name]
		if a == nil {
			a = &acc{site: protocol.WebSite{Name: clip(name, 256), Bindings: []protocol.WebBinding{}}, seen: map[string]bool{}}
			byName[name] = a
			order = append(order, name)
		}
		a.site.Upstreams = addUpstreams(a.site.Upstreams, r.upstreams...)
		for _, b := range r.bindings {
			b.Host = host
			key := b.Protocol + "|" + strconv.Itoa(b.Port) + "|" + b.Host
			if !a.seen[key] && len(a.site.Bindings) < protocol.MaxBindingsPerSite {
				a.seen[key] = true
				a.site.Bindings = append(a.site.Bindings, b)
			}
		}
	}
	out := make([]protocol.WebSite, 0, len(order))
	for _, n := range order {
		if len(out) == protocol.MaxIISSites {
			break
		}
		out = append(out, byName[n].site)
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
