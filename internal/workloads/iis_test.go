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
