// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"encoding/json"
	"strings"
	"testing"
)

// Trimmed applicationHost.config with the kinds of secrets IIS can store:
// none of them may appear in the output.
const appHost = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <applicationPools>
      <add name="PortalPool">
        <processModel identityType="SpecificUser" userName="CORP\svc_portal" password="[enc:IISCngProvider:SECRET:enc]" />
      </add>
    </applicationPools>
    <sites>
      <site name="Default Web Site" id="1" serverAutoStart="true">
        <application path="/" applicationPool="DefaultAppPool">
          <virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" />
        </application>
        <bindings>
          <binding protocol="http" bindingInformation="*:80:" />
          <binding protocol="net.tcp" bindingInformation="808:*" />
        </bindings>
      </site>
      <site name="Portal" id="2">
        <application path="/" applicationPool="PortalPool">
          <virtualDirectory path="/" physicalPath="D:\sites\portal" userName="CORP\share" password="[enc:AesProvider:SECRET2:enc]" />
        </application>
        <bindings>
          <binding protocol="https" bindingInformation="*:443:Portal.corp.local" sslFlags="1" />
          <binding protocol="http" bindingInformation="[::1]:8080:" />
          <binding protocol="http" bindingInformation="garbage" />
        </bindings>
      </site>
      <siteDefaults><logFile directory="C:\logs" /></siteDefaults>
    </sites>
  </system.applicationHost>
</configuration>`

func TestParseApplicationHost(t *testing.T) {
	sites, err := ParseApplicationHost(strings.NewReader(appHost))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(sites)
	want := `[{"name":"Default Web Site","bindings":[{"protocol":"http","port":80}]},` +
		`{"name":"Portal","bindings":[{"protocol":"https","port":443,"host":"portal.corp.local"},{"protocol":"http","port":8080}]}]`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	for _, secret := range []string{"SECRET", "svc_portal", "inetpub", "portal\\", "PortalPool", "logs"} {
		if strings.Contains(string(got), secret) {
			t.Fatalf("output leaks %q: %s", secret, got)
		}
	}
}

func TestParseApplicationHostWithoutSites(t *testing.T) {
	sites, err := ParseApplicationHost(strings.NewReader(`<configuration><system.webServer/></configuration>`))
	if err != nil || len(sites) != 0 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	if _, err := ParseApplicationHost(strings.NewReader(`<configuration><sites>`)); err == nil {
		t.Fatal("truncated XML should fail")
	}
}

func TestParsePoolSites(t *testing.T) {
	conf := `<configuration><system.applicationHost><sites>
      <site name="Billing" id="3">
        <application path="/" applicationPool="BillingPool" />
        <application path="/api" />
        <applicationDefaults applicationPool="BillingApi" />
      </site>
      <site name="Intranet" id="4">
        <application path="/" />
        <application path="/hr" applicationPool="SharedPool" />
      </site>
      <site name="Wiki" id="5"><application path="/" applicationPool="sharedpool" /></site>
      <applicationDefaults applicationPool="FallbackPool" />
    </sites></system.applicationHost></configuration>`
	pools, err := ParsePoolSites(strings.NewReader(appHost))
	if err != nil {
		t.Fatal(err)
	}
	if SiteOfPool(pools, "PortalPool") != "Portal" || SiteOfPool(pools, "defaultapppool") != "Default Web Site" {
		t.Fatalf("explicit pools: %v", pools)
	}
	pools, err = ParsePoolSites(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"BillingPool":  "Billing",
		"BillingApi":   "Billing",  // the site's own default, declared after the application
		"FallbackPool": "Intranet", // <sites> default, declared after every site
		"SharedPool":   "",         // Intranet and Wiki (case-insensitive)
		"Unknown":      "",
	}
	for pool, want := range cases {
		if got := SiteOfPool(pools, pool); got != want {
			t.Errorf("SiteOfPool(%q) = %q, want %q (%v)", pool, got, want, pools)
		}
	}
}

func TestParseWorkerProcesses(t *testing.T) {
	xmlOut := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<appcmd>
    <WP WP.NAME="3784" APPPOOL.NAME="DefaultAppPool" />
    <WP WP.NAME="5120" APPPOOL.NAME="BillingPool" />
    <WP WP.NAME="x" APPPOOL.NAME="Broken" />
</appcmd>`)
	got := ParseWorkerProcesses(xmlOut)
	if len(got) != 2 || got[3784] != "DefaultAppPool" || got[5120] != "BillingPool" {
		t.Fatalf("xml: %v", got)
	}
	text := []byte("WP \"3784\" (applicationPool:DefaultAppPool)\r\nWP \"5120\" (applicationPool:Billing Pool)\r\n")
	got = ParseWorkerProcesses(text)
	if len(got) != 2 || got[5120] != "Billing Pool" {
		t.Fatalf("text: %v", got)
	}
	if len(ParseWorkerProcesses(nil)) != 0 {
		t.Fatal("empty output should give no workers")
	}
}
