// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

const collectTimeout = 2 * time.Minute

// VCenter reads hosts and VMs from vCenter or a standalone ESXi host through
// the vSphere SOAP API (/sdk), read-only: RetrieveServiceContent, Login,
// CreateContainerView, RetrievePropertiesEx, DestroyView, Logout — nothing
// else. Hand-written (a few hundred lines) instead of govmomi, whose type
// catalogue would add ~7 MB to the agent; govmomi's simulator tests it.
// Only names, placement, size, power state, guest OS, guest host name and
// guest IPs are kept.
type VCenter struct {
	sdk      string
	username string
	password string
	tls      *tls.Config
}

// NewVCenter validates the local configuration and reads the password file.
func NewVCenter(c config.VCenterCollector) (*VCenter, error) {
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("vcenter: url must be https://host[:port] without credentials")
	}
	if strings.TrimSpace(c.Username) == "" {
		return nil, errors.New("vcenter: username is required")
	}
	password, err := readSecretFile("vcenter", "passwordFile", c.PasswordFile)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case c.CAFile != "":
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("vcenter: read caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("vcenter: caFile has no PEM certificates")
		}
		tlsConf.RootCAs = pool
	case c.InsecureSkipVerify:
		tlsConf.InsecureSkipVerify = true // only settable in the local config file
	}
	return &VCenter{sdk: u.Scheme + "://" + u.Host + "/sdk", username: c.Username, password: password, tls: tlsConf}, nil
}

// readSecretFile reads a private file holding one secret (no JSON, no key=value).
func readSecretFile(collector, field, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%s: %s is required", collector, field)
	}
	if err := checkPrivate(path); err != nil {
		return "", fmt.Errorf("%s: %s: %w", collector, field, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: read %s: %w", collector, field, err)
	}
	secret := strings.TrimSpace(string(b))
	if secret == "" || len(secret) > 4096 || strings.ContainsAny(secret, "\r\n") {
		return "", fmt.Errorf("%s: %s must contain only the secret, on one line", collector, field)
	}
	return secret, nil
}

// ───────────────────────── minimal SOAP client ─────────────────────────

type soapClient struct {
	sdk  string
	http *http.Client
}

var errLogin = errors.New("vcenter: login failed — check the username and the password file")

type soapFault struct {
	String string `xml:"faultstring"`
	Detail struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"detail"`
}

// call posts one vim25 request body and decodes the response element into out.
func (s *soapClient) call(ctx context.Context, body string, out any) error {
	envelope := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
		`<soapenv:Body>` + body + `</soapenv:Body></soapenv:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.sdk, strings.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "urn:vim25/8.0")
	res, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("vcenter: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("vcenter: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return errors.New("vcenter: response too large")
	}
	var env struct {
		Body struct {
			Fault *soapFault `xml:"Fault"`
			Inner []byte     `xml:",innerxml"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("vcenter: unexpected response (HTTP %d)", res.StatusCode)
	}
	if f := env.Body.Fault; f != nil {
		if bytes.Contains(f.Detail.Inner, []byte("InvalidLogin")) {
			return errLogin
		}
		msg := f.String
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("vcenter: %s", msg)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("vcenter: unexpected HTTP %d", res.StatusCode)
	}
	if out == nil {
		return nil
	}
	return xml.Unmarshal(env.Body.Inner, out)
}

type moRef struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

func (r moRef) xml(tag string) string {
	var b strings.Builder
	b.WriteString("<" + tag + ` type="`)
	_ = xml.EscapeText(&b, []byte(r.Type))
	b.WriteString(`">`)
	_ = xml.EscapeText(&b, []byte(r.Value))
	b.WriteString("</" + tag + ">")
	return b.String()
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

type serviceContent struct {
	RootFolder        moRef `xml:"returnval>rootFolder"`
	PropertyCollector moRef `xml:"returnval>propertyCollector"`
	ViewManager       moRef `xml:"returnval>viewManager"`
	SessionManager    moRef `xml:"returnval>sessionManager"`
}

// propValue keeps a property's raw XML: most are text, some are nested.
type propValue struct {
	Type  string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Text  string `xml:",chardata"`
	Inner []byte `xml:",innerxml"`
}

type objectContent struct {
	Obj     moRef `xml:"obj"`
	PropSet []struct {
		Name string    `xml:"name"`
		Val  propValue `xml:"val"`
	} `xml:"propSet"`
}

type retrieveResult struct {
	Token   string          `xml:"returnval>token"`
	Objects []objectContent `xml:"returnval>objects"`
}

var (
	hostPaths    = []string{"name", "parent", "summary.runtime.connectionState", "summary.config.product.fullName"}
	vmPaths      = []string{"name", "config.template", "config.guestFullName", "config.hardware.numCPU", "config.hardware.memoryMB", "runtime.host", "runtime.powerState", "guest.hostName", "guest.ipAddress", "guest.net"}
	clusterPaths = []string{"name"}
)

func propSpec(kind string, paths []string) string {
	var b strings.Builder
	b.WriteString("<propSet><type>" + kind + "</type>")
	for _, p := range paths {
		b.WriteString("<pathSet>" + p + "</pathSet>")
	}
	b.WriteString("</propSet>")
	return b.String()
}

// Collect logs in, reads the properties through one container view and logs out.
func (v *VCenter) Collect(ctx context.Context) (*protocol.Hypervisor, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	jar, _ := cookiejar.New(nil) // holds the vmware_soap_session cookie only for this collection
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = v.tls
	s := &soapClient{sdk: v.sdk, http: &http.Client{
		Timeout: requestTimeout, Transport: transport, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}

	var sc serviceContent
	if err := s.call(ctx, `<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>`, &sc); err != nil {
		return nil, err
	}
	if sc.SessionManager.Value == "" || sc.PropertyCollector.Value == "" || sc.ViewManager.Value == "" {
		return nil, errors.New("vcenter: not a vSphere API endpoint")
	}
	if err := s.call(ctx, `<Login xmlns="urn:vim25">`+sc.SessionManager.xml("_this")+
		`<userName>`+esc(v.username)+`</userName><password>`+esc(v.password)+`</password></Login>`, nil); err != nil {
		if errors.Is(err, errLogin) {
			return nil, errLogin
		}
		return nil, errLogin // never echo a fault that followed a login attempt
	}
	defer func() {
		logoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.call(logoutCtx, `<Logout xmlns="urn:vim25">`+sc.SessionManager.xml("_this")+`</Logout>`, nil)
	}()

	var view struct {
		Ref moRef `xml:"returnval"`
	}
	if err := s.call(ctx, `<CreateContainerView xmlns="urn:vim25">`+sc.ViewManager.xml("_this")+sc.RootFolder.xml("container")+
		`<type>HostSystem</type><type>VirtualMachine</type><type>ClusterComputeResource</type><recursive>true</recursive></CreateContainerView>`, &view); err != nil {
		return nil, err
	}
	defer func() {
		_ = s.call(context.Background(), `<DestroyView xmlns="urn:vim25">`+view.Ref.xml("_this")+`</DestroyView>`, nil)
	}()

	spec := `<specSet>` + propSpec("HostSystem", hostPaths) + propSpec("VirtualMachine", vmPaths) + propSpec("ClusterComputeResource", clusterPaths) +
		`<objectSet>` + view.Ref.xml("obj") + `<skip>true</skip>` +
		`<selectSet xsi:type="TraversalSpec"><name>traverseEntities</name><type>ContainerView</type><path>view</path><skip>false</skip></selectSet>` +
		`</objectSet></specSet>`
	var objects []objectContent
	var res retrieveResult
	if err := s.call(ctx, `<RetrievePropertiesEx xmlns="urn:vim25">`+sc.PropertyCollector.xml("_this")+spec+`<options><maxObjects>1000</maxObjects></options></RetrievePropertiesEx>`, &res); err != nil {
		return nil, err
	}
	objects = append(objects, res.Objects...)
	for page := 0; res.Token != "" && page < 50; page++ {
		token := res.Token
		res = retrieveResult{}
		if err := s.call(ctx, `<ContinueRetrievePropertiesEx xmlns="urn:vim25">`+sc.PropertyCollector.xml("_this")+`<token>`+esc(token)+`</token></ContinueRetrievePropertiesEx>`, &res); err != nil {
			return nil, err
		}
		objects = append(objects, res.Objects...)
	}
	return vcenterInventory(objects), nil
}

func vcenterInventory(objects []objectContent) *protocol.Hypervisor {
	out := &protocol.Hypervisor{Source: "vcenter", CollectedAt: time.Now().UTC(), Hosts: []protocol.HypervisorHost{}, VMs: []protocol.VM{}}
	clusters := map[string]string{}
	for _, o := range objects {
		if o.Obj.Type == "ClusterComputeResource" {
			for _, p := range o.PropSet {
				if p.Name == "name" {
					clusters[o.Obj.Value] = p.Val.Text
				}
			}
		}
	}
	for _, o := range objects {
		props := map[string]propValue{}
		for _, p := range o.PropSet {
			props[p.Name] = p.Val
		}
		switch o.Obj.Type {
		case "HostSystem":
			if len(out.Hosts) >= protocol.MaxHypervisorHosts {
				continue
			}
			h := protocol.HypervisorHost{
				ID: clip(o.Obj.Value, 128), Name: clip(props["name"].Text, 253),
				Status:  clip(props["summary.runtime.connectionState"].Text, 32),
				Version: clip(props["summary.config.product.fullName"].Text, 128),
			}
			if parent := props["parent"]; parent.Type == "ManagedObjectReference" {
				h.Cluster = clip(clusters[parent.Text], 128) // standalone hosts: none
			}
			if h.ID != "" && h.Name != "" {
				out.Hosts = append(out.Hosts, h)
			}
		case "VirtualMachine":
			if len(out.VMs) >= protocol.MaxInventoryItems {
				continue
			}
			vm := protocol.VM{
				ID: clip(o.Obj.Value, 128), Name: clip(props["name"].Text, 253),
				Host:     clip(props["runtime.host"].Text, 128),
				Status:   clip(props["runtime.powerState"].Text, 32),
				OS:       clip(props["config.guestFullName"].Text, 128),
				Hostname: clip(props["guest.hostName"].Text, 253),
				Template: props["config.template"].Text == "true",
			}
			vm.CPUs, _ = strconv.Atoi(props["config.hardware.numCPU"].Text)
			vm.MemoryMB, _ = strconv.Atoi(props["config.hardware.memoryMB"].Text)
			vm.CPUs, vm.MemoryMB = max(vm.CPUs, 0), max(vm.MemoryMB, 0)
			ips := []string{props["guest.ipAddress"].Text}
			var nics struct {
				Nics []struct {
					IPs []string `xml:"ipAddress"`
				} `xml:"GuestNicInfo"`
			}
			if raw := props["guest.net"].Inner; len(raw) > 0 {
				_ = xml.Unmarshal(append(append([]byte("<x>"), raw...), "</x>"...), &nics)
			}
			for _, n := range nics.Nics {
				ips = append(ips, n.IPs...)
			}
			vm.IPs = usableIPs(ips)
			if vm.ID != "" && vm.Name != "" {
				out.VMs = append(out.VMs, vm)
			}
		}
	}
	return out
}

// usableIPs keeps unique, parseable, non-loopback, non-link-local addresses.
func usableIPs(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		v := ip.String()
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) == protocol.MaxVMIPs {
			break
		}
	}
	return out
}
