// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseNginx(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/nginx/nginx.conf": {Data: []byte(`
user www-data;
events { worker_connections 768; }
http {
    ssl_certificate /etc/ssl/certs/SECRET-cert.pem;
    include /etc/nginx/conf.d/*.conf;
    include sites-enabled/*;
}
stream {
    server { listen 3306; proxy_pass db:3306; }   # TCP proxy: not a web site
}`)},
		"etc/nginx/conf.d/upstream.conf": {Data: []byte(`upstream app { server 127.0.0.1:3000; }`)},
		"etc/nginx/sites-enabled/shop": {Data: []byte(`
# Shop: http → https
server {
    listen 80;
    listen [::]:80;
    server_name shop.example.com www.shop.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl;
    server_name "shop.example.com";
    ssl_certificate_key /etc/ssl/private/SECRET.key;
    location / { proxy_pass http://app; }
}`)},
		"etc/nginx/sites-enabled/default": {Data: []byte(`
server {
    listen 8080 default_server;
    server_name _;
    root /var/www/SECRET-html;
}
server {
    listen unix:/run/app.sock;
    server_name internal.local;
}
server { server_name ~^(www\.)?(?<d>.+)$; }`)},
	}
	sites, err := ParseNginx(fsys, "/etc/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	got := mustJSON(t, sites)
	// Includes are read in name order (default before shop); the unix-socket
	// server is not reachable over TCP and is left out.
	want := `[{"name":"default (port 8080)","bindings":[{"protocol":"http","port":8080}]},` +
		`{"name":"default (port 80)","bindings":[{"protocol":"http","port":80}]},` +
		`{"name":"shop.example.com","bindings":[` +
		`{"protocol":"http","port":80,"host":"shop.example.com"},` +
		`{"protocol":"https","port":443,"host":"shop.example.com"}]}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "SECRET") || strings.Contains(got, "3306") {
		t.Fatalf("leaked or wrong context: %s", got)
	}
}

func TestParseApache(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/apache2/apache2.conf": {Data: []byte(`
ServerRoot "/etc/apache2"
Include ports.conf
IncludeOptional sites-enabled/*.conf
`)},
		"etc/apache2/ports.conf": {Data: []byte("Listen 80\nListen 443\n")},
		"etc/apache2/sites-enabled/000-default.conf": {Data: []byte(`
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/SECRET
</VirtualHost>`)},
		"etc/apache2/sites-enabled/intranet.conf": {Data: []byte(`
<VirtualHost *:80>
    ServerName intranet.corp.local
    Redirect / https://intranet.corp.local/
</VirtualHost>
<VirtualHost _default_:8443 [::]:8443>
    ServerName https://Intranet.corp.local:8443
    ServerAlias wiki.corp.local *.corp.local
    SSLEngine on
    SSLCertificateKeyFile /etc/ssl/private/SECRET.key
</VirtualHost>`)},
	}
	sites, err := ParseApache(fsys, "/etc/apache2/apache2.conf")
	if err != nil {
		t.Fatal(err)
	}
	got := mustJSON(t, sites)
	want := `[{"name":"default (port 80)","bindings":[{"protocol":"http","port":80}]},` +
		`{"name":"intranet.corp.local","bindings":[` +
		`{"protocol":"http","port":80,"host":"intranet.corp.local"},` +
		`{"protocol":"https","port":8443,"host":"intranet.corp.local"}]}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "SECRET") {
		t.Fatalf("leaked: %s", got)
	}
}

func TestConfigLoopsAreHarmless(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/nginx/nginx.conf": {Data: []byte(`http { include /etc/nginx/nginx.conf; server { listen 81; server_name a; } }`)},
	}
	sites, err := ParseNginx(fsys, "/etc/nginx/nginx.conf")
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	if _, err := ParseNginx(fstest.MapFS{}, "/etc/nginx/nginx.conf"); err == nil {
		t.Fatal("a missing main file is an error")
	}
}
