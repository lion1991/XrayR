package controller_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	_ "github.com/XrayR-project/XrayR/cmd/distro/all"
	"github.com/XrayR-project/XrayR/common/mylego"
	. "github.com/XrayR-project/XrayR/service/controller"
)

func rawURL32(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// TestSmokeRealityVlessBoots is the upgrade smoke test: it builds a VLESS +
// REALITY inbound through XrayR's own InboundBuilder (exercising the new
// mldsa65 / LimitFallback / plural-serverNames wiring) and actually boots it
// inside the upgraded xray-core runtime. If the bumped core changed the
// REALITY proto/config surface incompatibly, either InboundBuilder().Build()
// or server.Start() fails here.
func TestSmokeRealityVlessBoots(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Vless",
		NodeID:            1,
		Port:              14443,
		TransportProtocol: "tcp",
		EnableVless:       true,
		VlessFlow:         "xtls-rprx-vision",
		EnableREALITY:     true,
		REALITYConfig: &api.REALITYConfig{
			Dest:                  "www.cloudflare.com:443",
			ProxyProtocolVer:      0,
			ServerNames:           []string{"www.cloudflare.com", "cloudflare.com"}, // plural
			PrivateKey:            rawURL32(t),
			ShortIds:              []string{"aabb", "ccdd"}, // plural
			Mldsa65Seed:           rawURL32(t),              // post-quantum seed
			Show:                  false,
			LimitFallbackUpload:   api.LimitFallback{AfterBytes: 1000, BytesPerSec: 2000, BurstBytesPerSec: 3000},
			LimitFallbackDownload: api.LimitFallback{AfterBytes: 1000, BytesPerSec: 2000, BurstBytesPerSec: 3000},
		},
	}

	cfg := &Config{
		ListenIP:                  "127.0.0.1",
		DisableLocalREALITYConfig: true,
		CertConfig:                &mylego.CertConfig{CertMode: "none"},
	}

	ib, err := InboundBuilder(cfg, nodeInfo, "smoke-reality-vless")
	if err != nil {
		t.Fatalf("InboundBuilder failed (REALITY conf -> proto broke on upgrade?): %v", err)
	}

	policyConfig := &conf.PolicyConfig{}
	policyConfig.Levels = map[uint32]*conf.Policy{0: {StatsUserUplink: true, StatsUserDownlink: true}}
	pc, err := policyConfig.Build()
	if err != nil {
		t.Fatalf("policy build: %v", err)
	}
	dnsConfig, err := (&conf.DNSConfig{}).Build()
	if err != nil {
		t.Fatalf("dns build: %v", err)
	}
	routeConfig, err := (&conf.RouterConfig{}).Build()
	if err != nil {
		t.Fatalf("route build: %v", err)
	}
	ob, err := (&conf.OutboundDetourConfig{Protocol: "freedom", Tag: "direct"}).Build()
	if err != nil {
		t.Fatalf("freedom outbound build: %v", err)
	}

	coreConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage((&conf.LogConfig{}).Build()),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(pc),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  []*core.InboundHandlerConfig{ib},
		Outbound: []*core.OutboundHandlerConfig{ob},
	}

	server, err := core.New(coreConfig)
	if err != nil {
		t.Fatalf("core.New failed: %v", err)
	}
	defer server.Close()
	if err := server.Start(); err != nil {
		t.Fatalf("server.Start failed (REALITY/VLESS inbound did not come up): %v", err)
	}
	t.Log("OK: VLESS+REALITY (mldsa65 + LimitFallback + plural SNI/shortId) inbound booted on upgraded xray-core")
}
