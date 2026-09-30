// SPDX-License-Identifier: AGPL-3.0-only
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
	"sort"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

// XenOrchestra reads XCP-ng hosts and VMs from Xen Orchestra's REST API
// (/rest/v0, GET only) with the token of a user that can only view.
type XenOrchestra struct {
	base  string
	token string
	http  *http.Client
}

// NewXenOrchestra validates the local configuration and reads the token file.
func NewXenOrchestra(c config.XenOrchestraCollector) (*XenOrchestra, error) {
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("xenorchestra: url must be https://host[:port] without credentials")
	}
	token, err := readSecretFile("xenorchestra", "tokenFile", c.TokenFile)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.CAFile != "":
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("xenorchestra: read caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("xenorchestra: caFile has no PEM certificates")
		}
		tlsConf.RootCAs = pool
	case c.InsecureSkipVerify:
		tlsConf.InsecureSkipVerify = true // only settable in the local config file
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConf
	return &XenOrchestra{
		base:  u.String() + "/rest/v0",
		token: token,
		http: &http.Client{
			Timeout:       requestTimeout,
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type xoPool struct {
	ID        string `json:"id"`
	NameLabel string `json:"name_label"`
}

type xoHost struct {
	ID           string `json:"id"`
	NameLabel    string `json:"name_label"`
	PowerState   string `json:"power_state"`
	Version      string `json:"version"`
	ProductBrand string `json:"productBrand"`
	Pool         string `json:"$pool"`
}

type xoVM struct {
	ID         string               `json:"id"`
	NameLabel  string               `json:"name_label"`
	PowerState string               `json:"power_state"`
	Container  string               `json:"$container"` // host id when running, else the pool id
	CPUs       struct{ Number int } `json:"CPUs"`
	Memory     struct{ Size int64 } `json:"memory"`
	Addresses  map[string]string    `json:"addresses"`
	OSVersion  *struct {
		Name string `json:"name"`
	} `json:"os_version"`
}

func (x *XenOrchestra) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x.base+path, nil)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{Name: "authenticationToken", Value: x.token})
	req.Header.Set("Accept", "application/json")
	res, err := x.http.Do(req)
	if err != nil {
		return fmt.Errorf("xenorchestra: %w", err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return fmt.Errorf("xenorchestra: %s (check the token; tokens expire — create a new one)", res.Status)
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("xenorchestra: unexpected %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("xenorchestra: %w", err)
	}
	if len(body) > maxResponseBytes {
		return errors.New("xenorchestra: response too large")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("xenorchestra: invalid JSON: %w", err)
	}
	return nil
}

// Collect reads pools, hosts and VMs (templates live in another collection).
func (x *XenOrchestra) Collect(ctx context.Context) (*protocol.Hypervisor, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	var pools []xoPool
	var hosts []xoHost
	var vms []xoVM
	if err := x.get(ctx, "/pools?fields=id,name_label", &pools); err != nil {
		return nil, err
	}
	if err := x.get(ctx, "/hosts?fields=id,name_label,power_state,version,productBrand,$pool", &hosts); err != nil {
		return nil, err
	}
	if err := x.get(ctx, "/vms?fields=id,name_label,power_state,$container,CPUs,memory,addresses,os_version", &vms); err != nil {
		return nil, err
	}
	return xoInventory(pools, hosts, vms), nil
}

func xoInventory(pools []xoPool, hosts []xoHost, vms []xoVM) *protocol.Hypervisor {
	out := &protocol.Hypervisor{Source: "xenorchestra", CollectedAt: time.Now().UTC(), Hosts: []protocol.HypervisorHost{}, VMs: []protocol.VM{}}
	poolName := map[string]string{}
	for _, p := range pools {
		poolName[p.ID] = p.NameLabel
	}
	hostIDs := map[string]bool{}
	for _, h := range hosts {
		if h.ID == "" || h.NameLabel == "" || len(out.Hosts) >= protocol.MaxHypervisorHosts {
			continue
		}
		hostIDs[h.ID] = true
		out.Hosts = append(out.Hosts, protocol.HypervisorHost{
			ID: clip(h.ID, 128), Name: clip(h.NameLabel, 253), Cluster: clip(poolName[h.Pool], 128),
			Status: clip(h.PowerState, 32), Version: clip(strings.TrimSpace(h.ProductBrand+" "+h.Version), 128),
		})
	}
	for _, v := range vms {
		if v.ID == "" || v.NameLabel == "" || len(out.VMs) >= protocol.MaxInventoryItems {
			continue
		}
		vm := protocol.VM{
			ID: clip(v.ID, 128), Name: clip(v.NameLabel, 253), Status: clip(v.PowerState, 32),
			CPUs: max(v.CPUs.Number, 0), MemoryMB: int(max(v.Memory.Size, 0) / (1 << 20)),
		}
		if hostIDs[v.Container] { // halted VMs sit on the pool: no placement
			vm.Host = clip(v.Container, 128)
		}
		if v.OSVersion != nil {
			vm.OS = clip(v.OSVersion.Name, 128)
		}
		// "0/ipv4/0" keys: sort so the order is stable across collections.
		keys := make([]string, 0, len(v.Addresses))
		for k := range v.Addresses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ips := make([]string, 0, len(keys))
		for _, k := range keys {
			ips = append(ips, v.Addresses[k])
		}
		vm.IPs = usableIPs(ips)
		out.VMs = append(out.VMs, vm)
	}
	return out
}
