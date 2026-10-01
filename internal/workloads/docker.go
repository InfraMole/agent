// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

// DockerSocket is the Engine API socket read by the container collector.
var DockerSocket = "/var/run/docker.sock"

const (
	maxContainers      = 500
	maxDockerBodyBytes = 8 << 20
)

// dockerContainer: the fields of GET /containers/json the agent reads. The
// list endpoint carries no environment variables (unlike /containers/{id}/json,
// which the agent never calls).
type dockerContainer struct {
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

// dockerContainers lists the containers through the local Engine API
// (GET only). found=false when there is no Docker on this host.
func dockerContainers(ctx context.Context) ([]protocol.Container, bool, error) {
	if _, err := os.Stat(DockerSocket); err != nil {
		return nil, false, nil
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", DockerSocket)
		}},
	}
	var list []dockerContainer
	if err := dockerGet(ctx, client, "/containers/json?all=1", &list); err != nil {
		return nil, true, err
	}
	// A container whose image tag moved on shows "sha256:…": name it from the
	// image list (repository tags only).
	var images []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
	}
	if err := dockerGet(ctx, client, "/images/json", &images); err == nil {
		tags := map[string]string{}
		for _, im := range images {
			for _, t := range im.RepoTags {
				if t != "" && t != "<none>:<none>" {
					tags[im.ID] = t
					break
				}
			}
		}
		for i, c := range list {
			if strings.HasPrefix(c.Image, "sha256:") && tags[c.ImageID] != "" {
				list[i].Image = tags[c.ImageID]
			}
		}
	}
	return toContainers(list), true, nil
}

func dockerGet(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: unexpected %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxDockerBodyBytes+1))
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	if len(body) > maxDockerBodyBytes {
		return errors.New("docker: response too large")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("docker: invalid JSON: %w", err)
	}
	return nil
}

// toContainers keeps names, image, state, published ports, the Compose
// project / service / depends_on and the host names of reverse-proxy routes.
// Every other label is dropped (labels can hold credentials, e.g. Traefik
// basic-auth hashes).
func toContainers(list []dockerContainer) []protocol.Container {
	out := []protocol.Container{}
	for _, c := range list {
		if len(out) >= maxContainers || len(c.Names) == 0 || c.Image == "" {
			continue
		}
		ct := protocol.Container{
			Name:  clip(strings.TrimPrefix(c.Names[0], "/"), 256),
			Image: clip(c.Image, 512),
			State: clip(c.State, 32),
			Ports: []protocol.ContainerPort{},
		}
		seen := map[string]bool{}
		for _, p := range c.Ports {
			key := fmt.Sprintf("%d/%d/%s", p.PublicPort, p.PrivatePort, p.Type)
			if p.PublicPort <= 0 || p.PublicPort > 65535 || p.PrivatePort <= 0 || seen[key] || len(ct.Ports) >= 64 {
				continue // not published, or the IPv4/IPv6 duplicate
			}
			proto := strings.ToLower(p.Type)
			if proto != "tcp" && proto != "udp" && proto != "sctp" {
				continue
			}
			seen[key] = true
			ct.Ports = append(ct.Ports, protocol.ContainerPort{Port: p.PublicPort, TargetPort: p.PrivatePort, Protocol: proto})
		}
		l := c.Labels
		ct.Project = clip(l["com.docker.compose.project"], 128)
		ct.Service = clip(l["com.docker.compose.service"], 128)
		ct.DependsOn = composeDependsOn(l["com.docker.compose.depends_on"])
		ct.Hosts = proxyHosts(l)
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// composeDependsOn parses Compose's "db:service_started:false,redis:service_healthy:true".
func composeDependsOn(label string) []string {
	var out []string
	for _, part := range strings.Split(label, ",") {
		name := strings.TrimSpace(strings.SplitN(part, ":", 2)[0])
		if name != "" && len(name) <= 128 && len(out) < 32 {
			out = append(out, name)
		}
	}
	return out
}

var (
	traefikRule = regexp.MustCompile(`^traefik\.http\.routers\.[^.]+\.rule$`)
	hostMatcher = regexp.MustCompile("Host\\(([^)]*)\\)")
	hostQuoted  = regexp.MustCompile("[`\"']([^`\"']+)[`\"']")
	hostName    = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// proxyHosts: host names from Traefik router rules (Host(`a`, `b`)) and
// caddy-docker-proxy labels ("caddy": "a.example.com b.example.com").
func proxyHosts(labels map[string]string) []string {
	if labels["traefik.enable"] == "false" {
		return nil
	}
	set := map[string]bool{}
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) <= 253 && hostName.MatchString(h) && len(set) < 32 {
			set[h] = true
		}
	}
	for k, v := range labels {
		switch {
		case traefikRule.MatchString(k):
			for _, m := range hostMatcher.FindAllStringSubmatch(v, -1) {
				for _, q := range hostQuoted.FindAllStringSubmatch(m[1], -1) {
					add(q[1])
				}
			}
		case k == "caddy" || (strings.HasPrefix(k, "caddy_") && !strings.Contains(k, ".")):
			for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' }) {
				add(strings.TrimPrefix(strings.TrimPrefix(f, "https://"), "http://"))
			}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
