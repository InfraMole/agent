// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmware/govmomi/simulator"

	"github.com/InfraMole/agent/internal/config"
)

// vcsim: a full in-memory vCenter (govmomi's simulator), the same one the
// vmware/vcsim image runs. Default model: 1 datacenter, 1 cluster of 3 hosts
// + 1 standalone host, 2 VMs per host/cluster resource pool.
// Logins are checked against vcUser / vcPass.
const (
	vcUser = "inframole@vsphere.local"
	vcPass = "correct-horse-battery"
)

func startVCSim(t *testing.T) (*simulator.Model, *simulator.Server) {
	t.Helper()
	model := simulator.VPX()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	model.Service.Listen = &url.URL{User: url.UserPassword(vcUser, vcPass)}
	model.Service.TLS = new(tls.Config) // the collector is https-only
	server := model.Service.NewServer()
	t.Cleanup(func() { server.Close(); model.Remove() })
	return model, server
}

func secretFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVCenterCollectsHostsAndVMs(t *testing.T) {
	_, server := startVCSim(t)
	v, err := NewVCenter(config.VCenterCollector{
		URL:                "https://" + server.URL.Host,
		Username:           vcUser,
		PasswordFile:       secretFile(t, vcPass),
		InsecureSkipVerify: true, // the simulator's certificate is self-signed
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := v.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Source != "vcenter" || len(inv.Hosts) != 4 || len(inv.VMs) == 0 {
		t.Fatalf("got %d hosts, %d vms", len(inv.Hosts), len(inv.VMs))
	}
	hostIDs := map[string]bool{}
	clustered := 0
	for _, h := range inv.Hosts {
		hostIDs[h.ID] = true
		if h.Cluster != "" {
			clustered++
		}
		if h.Status != "connected" || !strings.Contains(h.Version, "ESX") {
			t.Errorf("host %+v", h)
		}
	}
	if clustered != 3 {
		t.Errorf("clustered hosts = %d, want 3", clustered)
	}
	for _, vm := range inv.VMs {
		if !hostIDs[vm.Host] {
			t.Errorf("vm %s placed on unknown host %q", vm.Name, vm.Host)
		}
		if vm.CPUs == 0 || vm.MemoryMB == 0 || vm.Status == "" || vm.OS == "" {
			t.Errorf("vm %+v", vm)
		}
	}
}

func TestVCenterRejectsWrongPassword(t *testing.T) {
	_, server := startVCSim(t)
	v, err := NewVCenter(config.VCenterCollector{
		URL: "https://" + server.URL.Host, Username: vcUser,
		PasswordFile: secretFile(t, "definitely-wrong"), InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "login failed") || strings.Contains(err.Error(), "definitely-wrong") {
		t.Fatalf("err = %v", err)
	}
}

func TestVCenterConfigValidation(t *testing.T) {
	good := secretFile(t, "pw")
	for _, c := range []config.VCenterCollector{
		{URL: "http://vc.lan", Username: "u", PasswordFile: good},
		{URL: "https://user:pw@vc.lan", Username: "u", PasswordFile: good},
		{URL: "https://vc.lan", PasswordFile: good},
		{URL: "https://vc.lan", Username: "u"},
		{URL: "https://vc.lan", Username: "u", PasswordFile: secretFile(t, "a\nb")},
	} {
		if _, err := NewVCenter(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestUsableIPs(t *testing.T) {
	got := usableIPs([]string{"10.0.0.5", "fe80::1", "127.0.0.1", "10.0.0.5", "", "2001:db8::5", "junk"})
	if strings.Join(got, ",") != "10.0.0.5,2001:db8::5" {
		t.Fatalf("got %v", got)
	}
}

// A RetrievePropertiesEx body as vSphere returns it (typed values, nested
// GuestNicInfo), including a host in a cluster and a template.
func TestVCenterParsesPropertyValues(t *testing.T) {
	body := []byte(`<RetrievePropertiesExResponse xmlns="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><returnval>
<objects><obj type="ClusterComputeResource">domain-c7</obj><propSet><name>name</name><val xsi:type="xsd:string">Prod</val></propSet></objects>
<objects><obj type="HostSystem">host-21</obj>
 <propSet><name>name</name><val xsi:type="xsd:string">esx01.corp.local</val></propSet>
 <propSet><name>parent</name><val type="ClusterComputeResource" xsi:type="ManagedObjectReference">domain-c7</val></propSet>
 <propSet><name>summary.config.product.fullName</name><val xsi:type="xsd:string">VMware ESXi 8.0.3 build-24022510</val></propSet>
 <propSet><name>summary.runtime.connectionState</name><val xsi:type="HostSystemConnectionState">connected</val></propSet></objects>
<objects><obj type="VirtualMachine">vm-42</obj>
 <propSet><name>config.guestFullName</name><val xsi:type="xsd:string">Microsoft Windows Server 2022 (64-bit)</val></propSet>
 <propSet><name>config.hardware.memoryMB</name><val xsi:type="xsd:int">8192</val></propSet>
 <propSet><name>config.hardware.numCPU</name><val xsi:type="xsd:int">4</val></propSet>
 <propSet><name>config.template</name><val xsi:type="xsd:boolean">false</val></propSet>
 <propSet><name>guest.hostName</name><val xsi:type="xsd:string">app01.corp.local</val></propSet>
 <propSet><name>guest.ipAddress</name><val xsi:type="xsd:string">10.0.0.23</val></propSet>
 <propSet><name>guest.net</name><val xsi:type="ArrayOfGuestNicInfo">
   <GuestNicInfo><network>VM Network</network><ipAddress>10.0.0.23</ipAddress><ipAddress>fe80::250:56ff:fe8a:1</ipAddress><macAddress>00:50:56:8a:00:01</macAddress><connected>true</connected></GuestNicInfo>
   <GuestNicInfo><ipAddress>192.168.50.4</ipAddress></GuestNicInfo></val></propSet>
 <propSet><name>name</name><val xsi:type="xsd:string">app01-prod</val></propSet>
 <propSet><name>runtime.host</name><val type="HostSystem" xsi:type="ManagedObjectReference">host-21</val></propSet>
 <propSet><name>runtime.powerState</name><val xsi:type="VirtualMachinePowerState">poweredOn</val></propSet></objects>
<objects><obj type="VirtualMachine">vm-7</obj>
 <propSet><name>config.template</name><val xsi:type="xsd:boolean">true</val></propSet>
 <propSet><name>name</name><val xsi:type="xsd:string">tpl-win2022</val></propSet></objects>
</returnval></RetrievePropertiesExResponse>`)
	var res retrieveResult
	if err := xml.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	inv := vcenterInventory(res.Objects)
	if len(inv.Hosts) != 1 || inv.Hosts[0].Cluster != "Prod" || inv.Hosts[0].Status != "connected" || inv.Hosts[0].Version != "VMware ESXi 8.0.3 build-24022510" {
		t.Fatalf("hosts %+v", inv.Hosts)
	}
	app := inv.VMs[0]
	if app.Name != "app01-prod" || app.Host != "host-21" || app.CPUs != 4 || app.MemoryMB != 8192 ||
		app.Hostname != "app01.corp.local" || strings.Join(app.IPs, ",") != "10.0.0.23,192.168.50.4" || app.Template {
		t.Fatalf("vm %+v", app)
	}
	if !inv.VMs[1].Template {
		t.Fatal("template not flagged")
	}
}
