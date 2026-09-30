// SPDX-License-Identifier: AGPL-3.0-only
// Package inventory implements agent-side collectors (ADR-018 C): read-only
// calls to on-prem platform APIs, configured only in the local config file.
// Credentials never leave the machine; only the inventory fields the server
// imports are sent (protocol.InventoryItem).
package inventory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

const (
	maxResponseBytes = 16 << 20
	requestTimeout   = 30 * time.Second
)

// USER@REALM!TOKENID=SECRET, as shown by Proxmox when the token is created.
var tokenPattern = regexp.MustCompile(`^[^\s@=!]+@[^\s@=!]+![^\s@=!]+=[0-9a-fA-F-]{8,64}$`)

type Proxmox struct {
	endpoint string
	token    string
	http     *http.Client
}

// NewProxmox validates the local configuration and reads the token file.
func NewProxmox(c config.ProxmoxCollector) (*Proxmox, error) {
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("proxmox: url must be https://host[:port] without credentials")
	}
	token, err := readTokenFile(c.TokenFile)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.CAFile != "":
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("proxmox: read caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("proxmox: caFile has no PEM certificates")
		}
		tlsConf.RootCAs = pool
	case c.InsecureSkipVerify:
		// Only settable in the local config file, for self-signed PVE certificates.
		tlsConf.InsecureSkipVerify = true
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConf
	return &Proxmox{
		endpoint: u.String() + "/api2/json/cluster/resources",
		token:    token,
		http: &http.Client{
			Timeout:   requestTimeout,
			Transport: transport,
			// Never forward the token anywhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func readTokenFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("proxmox: tokenFile is required")
	}
	if err := checkPrivate(path); err != nil {
		return "", fmt.Errorf("proxmox: tokenFile: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("proxmox: read tokenFile: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if !tokenPattern.MatchString(token) {
		return "", errors.New("proxmox: tokenFile must contain USER@REALM!TOKENID=SECRET")
	}
	return token, nil
}

type pveResource struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Node     string  `json:"node"`
	Name     string  `json:"name"`
	VMID     int     `json:"vmid"`
	Status   string  `json:"status"`
	MaxMem   float64 `json:"maxmem"`
	Template int     `json:"template"`
}

// Collect calls GET /api2/json/cluster/resources (needs PVEAuditor on /).
func (p *Proxmox) Collect(ctx context.Context) (*protocol.Inventory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+p.token)
	req.Header.Set("Accept", "application/json")
	res, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxmox: %w", err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("proxmox: %s (check the token and that it has PVEAuditor on /)", res.Status)
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("proxmox: unexpected %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("proxmox: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("proxmox: response too large")
	}
	var out struct {
		Data []pveResource `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("proxmox: invalid JSON: %w", err)
	}
	return &protocol.Inventory{Source: "proxmox", CollectedAt: time.Now().UTC(), Items: toItems(out.Data)}, nil
}

// toItems keeps nodes, VMs and containers only, bounded and trimmed to the
// server's limits.
func toItems(in []pveResource) []protocol.InventoryItem {
	items := make([]protocol.InventoryItem, 0, len(in))
	for _, r := range in {
		if r.Type != "node" && r.Type != "qemu" && r.Type != "lxc" {
			continue
		}
		if r.ID == "" || len(items) >= protocol.MaxInventoryItems {
			continue
		}
		template := 0
		if r.Template == 1 {
			template = 1
		}
		items = append(items, protocol.InventoryItem{
			ID: clip(r.ID, 64), Type: r.Type, Node: clip(r.Node, 64), Name: clip(r.Name, 253),
			VMID: max(r.VMID, 0), Status: clip(r.Status, 32), MaxMem: max(r.MaxMem, 0), Template: template,
		})
	}
	return items
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
