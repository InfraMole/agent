// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/InfraMole/agent/internal/protocol"
)

func ups(list []protocol.Upstream) string {
	b, _ := json.Marshal(list)
	return string(b)
}

func TestParseUpstream(t *testing.T) {
	for in, want := range map[string]string{
		"http://10.0.0.5:8080/app?x=1": "10.0.0.5:8080",
		"https://api.corp.local":       "api.corp.local:443",
		"127.0.0.1:9000":               "127.0.0.1:9000",
		"http://user:pw@backend:81/":   "backend:81",
		"http://[::1]:3000":            "::1:3000",
		"http://unix:/run/app.sock:/":  "",
		"http://$backend":              "",
		"balancer://cluster/":          "",
		"":                             "",
	} {
		u, ok := parseUpstream(in)
		got := ""
		if ok {
			got = u.Host + ":" + itoa(u.Port)
		}
		if got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestNginxUpstreamBlocks(t *testing.T) {
	fsys := fstest.MapFS{"etc/nginx/nginx.conf": {Data: []byte(`
http {
  upstream app_pool { server 10.0.0.11:8080 weight=2; server 10.0.0.12:8080; server app3.lan; }
  server {
    listen 443 ssl; server_name app.example.com;
    ssl_certificate_key /etc/ssl/private/SECRET.key;
    location / { proxy_pass http://app_pool; proxy_set_header Authorization "Bearer SECRET"; }
    location /php { fastcgi_pass 127.0.0.1:9000; }
    location /ws { proxy_pass http://$upstream_var; }
  }
}`)}}
	sites, err := ParseNginx(fsys, "/etc/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	got := ups(sites[0].Upstreams)
	want := `[{"host":"10.0.0.11","port":8080},{"host":"10.0.0.12","port":8080},{"host":"app3.lan","port":80},{"host":"127.0.0.1","port":9000}]`
	if got != want || strings.Contains(got, "SECRET") {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestApacheProxyPass(t *testing.T) {
	fsys := fstest.MapFS{"etc/apache2/apache2.conf": {Data: []byte(`
<Proxy "balancer://api">
    BalancerMember "http://10.0.0.21:8000"
    BalancerMember "http://10.0.0.22:8000" loadfactor=2
</Proxy>
<VirtualHost *:443>
    ServerName www.example.com
    SSLEngine on
    ProxyPass "/api/" "balancer://api/"
    ProxyPass "/static/" "!"
    ProxyPass "/" "http://127.0.0.1:8080/"
    RewriteRule "^/legacy/(.*)" "http://legacy.lan:9090/$1" [P,L]
    RewriteRule "^/old/(.*)" "/new/$1" [R=301,L]
</VirtualHost>`)}}
	sites, err := ParseApache(fsys, "/etc/apache2/apache2.conf")
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"host":"10.0.0.21","port":8000},{"host":"10.0.0.22","port":8000},{"host":"127.0.0.1","port":8080},{"host":"legacy.lan","port":9090}]`
	if got := ups(sites[0].Upstreams); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestParseHAProxy(t *testing.T) {
	fsys := fstest.MapFS{"etc/haproxy/haproxy.cfg": {Data: []byte(`
global
    log /dev/log local0
defaults
    mode http
frontend web
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/SECRET.pem
    acl is_api path_beg /api
    use_backend api if is_api
    default_backend app
backend app
    server app1 10.0.0.31:8080 check
    server app2 10.0.0.32:8080 check
backend api
    server api1 api.lan:9000 check
listen stats
    bind :8404
    stats auth admin:SECRET
listen pg
    bind :5432
    server db1 10.0.0.40:5432 check
`)}}
	sites, err := ParseHAProxy(fsys, "/etc/haproxy/haproxy.cfg")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sites)
	got := string(b)
	want := `[{"name":"web","bindings":[{"protocol":"http","port":80},{"protocol":"https","port":443}],` +
		`"upstreams":[{"host":"api.lan","port":9000},{"host":"10.0.0.31","port":8080},{"host":"10.0.0.32","port":8080}]},` +
		`{"name":"stats","bindings":[{"protocol":"http","port":8404}]},` +
		`{"name":"pg","bindings":[{"protocol":"http","port":5432}],"upstreams":[{"host":"10.0.0.40","port":5432}]}]`
	if got != want || strings.Contains(got, "SECRET") {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestIISProxies(t *testing.T) {
	appHost := `<configuration>
 <system.applicationHost><sites>
  <site name="Portal" id="1"><application path="/" applicationPool="Portal">
   <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\portal" userName="CORP\svc" password="[enc:SECRET:enc]" /></application>
   <bindings><binding protocol="https" bindingInformation="*:443:portal.corp.local" /></bindings></site>
 </sites></system.applicationHost>
 <webFarms>
  <webFarm name="AppFarm" enabled="true">
   <server address="10.0.0.51" enabled="true"><applicationRequestRouting httpPort="8080" /></server>
   <server address="10.0.0.52" enabled="true" />
  </webFarm>
 </webFarms>
 <system.webServer><rewrite><globalRules>
  <rule name="ARR_AppFarm"><match url="api/(.*)" /><action type="Rewrite" url="http://AppFarm/{R:1}" /></rule>
 </globalRules></rewrite></system.webServer>
 <location path="Portal"><system.webServer><rewrite><rules>
  <rule name="legacy"><action type="Rewrite" url="http://legacy.corp.local:9000/{R:1}" /></rule>
  <rule name="local"><action type="Rewrite" url="/index.aspx" /></rule>
  <rule name="redir"><action type="Redirect" url="https://elsewhere.example.com/" /></rule>
 </rules></rewrite></system.webServer></location>
</configuration>`
	conf, err := parseIISProxies(strings.NewReader(appHost))
	if err != nil {
		t.Fatal(err)
	}
	if conf.roots["Portal"] != `%SystemDrive%\inetpub\portal` {
		t.Fatalf("roots %v", conf.roots)
	}
	got := ups(iisUpstreams(append(conf.global, conf.bySite["Portal"]...), conf.farms))
	want := `[{"host":"10.0.0.51","port":8080},{"host":"10.0.0.52","port":80},{"host":"legacy.corp.local","port":9000}]`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	webConfig := `<configuration><connectionStrings><add name="db" connectionString="Server=sql01;Password=SECRET" /></connectionStrings>
<system.webServer><rewrite><rules><rule name="api"><action type="Rewrite" url="http://10.0.0.60:5000/{R:1}" /></rule></rules></rewrite></system.webServer></configuration>`
	urls := webConfigRewrites(strings.NewReader(webConfig))
	if len(urls) != 1 || strings.Contains(strings.Join(urls, ""), "SECRET") {
		t.Fatalf("web.config urls %v", urls)
	}
}
