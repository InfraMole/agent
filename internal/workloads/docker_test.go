// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"encoding/json"
	"strings"
	"testing"
)

// A GET /containers/json answer (Engine API) with Compose and Traefik labels.
const containersJSON = `[
 {"Id":"a1","Names":["/shop-web-1"],"Image":"ghcr.io/acme/shop:1.4.2","State":"running","Status":"Up 2 hours",
  "Ports":[{"PrivatePort":8080,"Type":"tcp"}],
  "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web",
            "com.docker.compose.depends_on":"db:service_healthy:false,cache:service_started:false",
            "traefik.enable":"true",
            "traefik.http.routers.shop.rule":"Host(` + "`shop.example.com`" + `) || Host(` + "`www.shop.example.com`" + `) && PathPrefix(` + "`/`" + `)",
            "traefik.http.middlewares.auth.basicauth.users":"admin:$apr1$secret$hash",
            "com.example.api-key":"s3cr3t"}},
 {"Id":"b2","Names":["/shop-db-1"],"Image":"postgres:16-alpine","State":"running",
  "Ports":[{"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"},{"IP":"::","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"}],
  "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"}},
 {"Id":"c3","Names":["/traefik"],"Image":"traefik:v3.1","State":"running",
  "Ports":[{"PrivatePort":443,"PublicPort":443,"Type":"tcp"},{"PrivatePort":80,"PublicPort":80,"Type":"tcp"}],"Labels":{}},
 {"Id":"d4","Names":["/blog"],"Image":"ghost:5","State":"exited","Ports":[],
  "Labels":{"caddy":"blog.example.com","traefik.enable":"false"}}
]`

func TestToContainers(t *testing.T) {
	var list []dockerContainer
	if err := json.Unmarshal([]byte(containersJSON), &list); err != nil {
		t.Fatal(err)
	}
	got := toContainers(list)
	raw, _ := json.Marshal(got)
	for _, secret := range []string{"apr1", "s3cr3t", "basicauth", "api-key"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("label leaked: %s", secret)
		}
	}
	byName := map[string]int{}
	for i, c := range got {
		byName[c.Name] = i
	}
	web := got[byName["shop-web-1"]]
	if web.Project != "shop" || web.Service != "web" || strings.Join(web.DependsOn, ",") != "db,cache" ||
		strings.Join(web.Hosts, ",") != "shop.example.com,www.shop.example.com" || len(web.Ports) != 0 {
		t.Fatalf("web %+v", web)
	}
	db := got[byName["shop-db-1"]]
	if len(db.Ports) != 1 || db.Ports[0].Port != 5432 || db.Ports[0].Protocol != "tcp" {
		t.Fatalf("db ports %+v (IPv4/IPv6 duplicates must collapse)", db.Ports)
	}
	if blog := got[byName["blog"]]; len(blog.Hosts) != 0 {
		t.Fatalf("traefik.enable=false must disable routes: %+v", blog)
	}
}

func TestProxyHostsCaddy(t *testing.T) {
	got := proxyHosts(map[string]string{"caddy": "https://a.example.com, b.example.com", "caddy_1": "c.example.com", "caddy.reverse_proxy": "{{upstreams 80}}"})
	if strings.Join(got, ",") != "a.example.com,b.example.com,c.example.com" {
		t.Fatalf("got %v", got)
	}
}
