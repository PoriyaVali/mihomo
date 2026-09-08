package config

import "testing"

func TestParsePublicIPNameServerPreservesTransportAndProxy(t *testing.T) {
	servers, err := parseNameServer([]string{
		"178.22.122.100#dm-public-ip=true",
		"tcp://178.22.122.100#Wi-Fi&dm-public-ip=true",
		"https://dns.example/dns-query#DIRECT&skip-cert-verify=true&dm-public-ip=true",
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 3 || servers[0].Net != "" || servers[1].Net != "tcp" || servers[2].Net != "https" {
		t.Fatalf("transport parsing changed: %+v", servers)
	}
	for _, server := range servers {
		if server.Params["dm-public-ip"] != "true" {
			t.Fatalf("public validation option lost: %+v", server)
		}
	}
	if servers[1].ProxyName != "Wi-Fi" || servers[2].ProxyName != "DIRECT" || servers[2].Params["skip-cert-verify"] != "true" {
		t.Fatalf("existing fragment semantics changed: %+v", servers)
	}
}
