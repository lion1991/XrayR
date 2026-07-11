package keeper_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/keeper"
)

// panelServing stands up a fake keeper that answers /config with the given
// body, so the test drives the real GetNodeInfo path — including the decode
// into serverConfig, which is where the embedded-struct json tag traps live.
func panelServing(t *testing.T, configJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(configJSON))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func snellClient(t *testing.T, host string) *keeper.APIClient {
	t.Helper()
	return keeper.New(&api.Config{APIHost: host, Key: "k", NodeID: 1, NodeType: "Snell"})
}

func TestGetNodeInfoSnellV6(t *testing.T) {
	srv := panelServing(t, `{
		"protocol":"snell","listen_ip":"0.0.0.0","server_port":8443,
		"version":6,"psk":"0123456789abcdef","mode":"unshaped","obfs":null,
		"multi_user":true
	}`)

	node, err := snellClient(t, srv.URL).GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}

	if node.Port != 8443 {
		t.Errorf("Port = %d, want 8443", node.Port)
	}
	if node.SnellVersion != 6 {
		t.Errorf("SnellVersion = %d, want 6", node.SnellVersion)
	}
	if node.SnellPSK != "0123456789abcdef" {
		t.Errorf("SnellPSK = %q, want the panel psk", node.SnellPSK)
	}
	if node.SnellMode != "unshaped" {
		t.Errorf("SnellMode = %q, want unshaped", node.SnellMode)
	}
	if !node.SnellMultiUser {
		t.Error("SnellMultiUser = false, want true — the node would silently run unmetered")
	}
	// Snell is not a TLS protocol; asking for a cert would fail the node at boot.
	if node.EnableTLS {
		t.Error("EnableTLS = true for a Snell node, but Snell has no TLS layer")
	}
}

// keeper's Snell editor writes "off" to mean "no obfuscation", but sing-snell
// only accepts "" / none / http / tls and errors on anything else — so "off"
// has to be normalised away before it reaches the inbound.
func TestGetNodeInfoSnellObfsOffNormalised(t *testing.T) {
	srv := panelServing(t, `{"server_port":8443,"version":5,"psk":"psk-v5","obfs":"off"}`)

	node, err := snellClient(t, srv.URL).GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.SnellObfs != "" {
		t.Errorf("SnellObfs = %q, want \"\" — sing-snell rejects the literal \"off\"", node.SnellObfs)
	}
}

// A panel that omits `version` must land on 6, matching keeper's admin editor,
// rather than 0 — which the controller rejects outright.
func TestGetNodeInfoSnellVersionDefaultsTo6(t *testing.T) {
	srv := panelServing(t, `{"server_port":8443,"psk":"0123456789abcdef","mode":"default"}`)

	node, err := snellClient(t, srv.URL).GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if node.SnellVersion != 6 {
		t.Errorf("SnellVersion = %d, want 6 by default", node.SnellVersion)
	}
}

// Regression guard for a silent, protocol-crossing decode bug.
//
// serverConfig aggregates each protocol's fields as embedded structs. Go's
// encoding/json drops a key outright when two fields at the same depth claim
// the same tag — it does not pick one, it sets neither. Snell and Hysteria both
// have a `version`, so giving each its own embedded field would zero BOTH. And a
// Hysteria node whose version decodes to 0 rather than 2 does not fail: it
// quietly builds an Hy1 inbound instead of Hy2, and every client stops
// connecting for reasons no log explains.
//
// `version` therefore lives one level up, on serverConfig itself. This test
// fails the moment someone moves it back down.
func TestHysteriaVersionSurvivesSnellTagCollision(t *testing.T) {
	srv := panelServing(t, `{
		"server_port":443,"version":2,
		"up_mbps":100,"down_mbps":200,
		"obfs":"salamander","obfs-password":"obfs-pw"
	}`)

	c := keeper.New(&api.Config{APIHost: srv.URL, Key: "k", NodeID: 1, NodeType: "Hysteria"})
	node, err := c.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}

	if node.HysteriaVersion != 2 {
		t.Fatalf("HysteriaVersion = %d, want 2. A same-depth `version` json tag was reintroduced in an embedded struct, so encoding/json dropped the key — this node would silently downgrade from Hy2 to Hy1", node.HysteriaVersion)
	}
	if node.HysteriaObfs != "salamander" {
		t.Errorf("HysteriaObfs = %q, want salamander", node.HysteriaObfs)
	}
	if node.HysteriaObfsPassword != "obfs-pw" {
		t.Errorf("HysteriaObfsPassword = %q, want obfs-pw", node.HysteriaObfsPassword)
	}
	if node.HysteriaUpMbps != 100 || node.HysteriaDownMbps != 200 {
		t.Errorf("bandwidth = %d/%d, want 100/200", node.HysteriaUpMbps, node.HysteriaDownMbps)
	}
}

// In multi_user mode the user's uuid *is* their Snell key, so GetUserList must
// populate Passwd for Snell exactly as it does for the other uuid-keyed
// protocols. Without it the controller would refuse to build the inbound.
func TestGetUserListSnellPopulatesPasswd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/server/UniProxy/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":42,"uuid":"11111111-2222-3333-4444-555555555555","speed_limit":0}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	users, err := snellClient(t, srv.URL).GetUserList()
	if err != nil {
		t.Fatalf("GetUserList: %v", err)
	}
	if len(*users) != 1 {
		t.Fatalf("got %d users, want 1", len(*users))
	}
	u := (*users)[0]
	if u.Passwd != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("Passwd = %q, want the uuid — it is the per-user Snell key", u.Passwd)
	}
	if u.UID != 42 {
		t.Errorf("UID = %d, want 42", u.UID)
	}
}
