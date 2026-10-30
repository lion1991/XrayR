package controller_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	sboption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/mylego"
	. "github.com/XrayR-project/XrayR/service/controller"
)

const vision = "xtls-rprx-vision"

// startRealityTarget serves the TLS site a REALITY node borrows its
// handshake from, with the node.test certificate.
func startRealityTarget(t *testing.T) (addr string, certificate []byte) {
	t.Helper()
	certConfig := writeTestCert(t)
	cert, err := tls.LoadX509KeyPair(certConfig.CertFile, certConfig.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return l.Addr().String(), cert.Certificate[0]
}

type realityNode struct {
	fake       *fakeSnellAPI
	controller *SingBoxController
	addr       string
	publicKey  string
	target     []byte
}

// startVLESSNode serves a VLESS REALITY node with Vision as keeper describes
// one (tls 2), with no certificate configured.
func startVLESSNode(t *testing.T, change func(*api.NodeInfo, *Config)) *realityNode {
	t.Helper()
	return startVLESSNodeLogging(t, SingBoxLog{}, change)
}

func startVLESSNodeLogging(t *testing.T, logConfig SingBoxLog, change func(*api.NodeInfo, *Config)) *realityNode {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, certificate := startRealityTarget(t)
	port := freePort(t)
	nodeInfo := &api.NodeInfo{
		NodeType:          "Vless",
		NodeID:            1,
		Port:              uint32(port),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		EnableVless:       true,
		VlessFlow:         vision,
		EnableREALITY:     true,
		REALITYConfig: &api.REALITYConfig{
			Dest:        target,
			ServerNames: []string{"node.test"},
			PrivateKey:  base64.RawURLEncoding.EncodeToString(key.Bytes()),
			ShortIds:    []string{"aabbccdd"},
			MaxTimeDiff: 60_000,
		},
	}
	config := &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1, CertConfig: &mylego.CertConfig{CertMode: "none"}}
	if change != nil {
		change(nodeInfo, config)
	}
	if raceEnabled && nodeInfo.VlessFlow == vision {
		// No data race; rerun with -gcflags=all=-d=checkptr=0 to cover it.
		t.Skip("sing-vmess Vision does pointer arithmetic that -race's checkptr rejects (docs/plans/sing-box-migration.md)")
	}
	f := &fakeSnellAPI{
		nodeInfo: nodeInfo,
		users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID, Email: snellTestUUID + "@v2board.user"}},
	}
	c := NewTestSingBoxControllerLogging(f, config, logConfig)
	if err := c.Start(); err != nil {
		t.Fatalf("start VLESS node: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &realityNode{
		fake:       f,
		controller: c,
		addr:       net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		publicKey:  base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		target:     certificate,
	}
}

// realityConn is the REALITY handshake the wkernel outbound makes.
func (n *realityNode) realityConn(t *testing.T, shortID string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	config, err := sbtls.NewClient(ctx, logger.NOP(), "node.test", sboption.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "node.test",
		UTLS:       &sboption.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    &sboption.OutboundRealityOptions{Enabled: true, PublicKey: n.publicKey, ShortID: shortID},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", n.addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := sbtls.ClientHandshake(ctx, raw, config)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func (n *realityNode) proxies(t *testing.T, shortID, uuid, flow, echo string) bool {
	t.Helper()
	tlsConn, err := n.realityConn(t, shortID)
	if err != nil {
		return false
	}
	defer tlsConn.Close()
	client, err := vless.NewClient(uuid, flow, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialConn(tlsConn, M.ParseSocksaddr(echo))
	if err != nil {
		return false
	}
	got, err := echoThrough(conn, "probe")
	return err == nil && got == "probe"
}

func TestVLESSRealityNodeProxiesAndMeters(t *testing.T) {
	echo := startEchoServer(t)
	udpEcho := startUDPEchoServer(t)
	node := startVLESSNode(t, nil)

	if !node.proxies(t, "aabbccdd", snellTestUUID, vision, echo) {
		t.Fatal("uid 42 fails to proxy TCP over Vision")
	}
	if node.proxies(t, "aabbccdd", snellTestUUID2, vision, echo) {
		t.Fatal("an unknown uuid proxies")
	}
	if node.proxies(t, "11223344", snellTestUUID, vision, echo) {
		t.Fatal("an unknown short id proxies")
	}
	if node.proxies(t, "aabbccdd", snellTestUUID, "", echo) {
		t.Fatal("a client without the user's flow proxies")
	}

	// The wkernel outbound sends UDP as XUDP.
	tlsConn, err := node.realityConn(t, "aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()
	client, err := vless.NewClient(snellTestUUID, vision, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := client.DialEarlyXUDPPacketConn(tlsConn, M.ParseSocksaddr(udpEcho.String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packetConn.WriteTo([]byte("datagram"), udpEcho); err != nil {
		t.Fatalf("send UDP: %v", err)
	}
	received := make([]byte, 2048)
	n, _, err := packetConn.ReadFrom(received)
	if err != nil || string(received[:n]) != "datagram" {
		t.Fatalf("UDP echo: %q, %v", received[:n], err)
	}

	waitFor(t, "uid 42's traffic to be reported", func() bool {
		up, down := node.fake.trafficFor(42)
		return up >= int64(len("probe")+len("datagram")) && down >= int64(len("probe")+len("datagram"))
	})
}

// A client without the REALITY key, a prober, gets the target's site.
func TestVLESSRealityNodeShowsTargetToProbes(t *testing.T) {
	node := startVLESSNode(t, nil)
	conn, err := tls.Dial("tcp", node.addr, &tls.Config{ServerName: "node.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("probe handshake: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().PeerCertificates[0].Raw; string(got) != string(node.target) {
		t.Error("the probe did not get the target's certificate")
	}
}

func TestVLESSRealityNodeReplacesUsers(t *testing.T) {
	echo := startEchoServer(t)
	node := startVLESSNode(t, nil)
	generation := node.controller.BoxGeneration()
	node.fake.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"}})
	waitFor(t, "uid 43 to be admitted", func() bool {
		return node.proxies(t, "aabbccdd", snellTestUUID2, vision, echo)
	})
	if node.proxies(t, "aabbccdd", snellTestUUID, vision, echo) {
		t.Error("removed uid 42 still proxies")
	}
	if node.controller.BoxGeneration() != generation {
		t.Error("a user change rebuilt the box")
	}
}

// Inner TLS through Vision is metered. Vision switches to copying the
// connection as is here (seen with a probe in sing-vmess), but the test does
// not assert the switch, only the metering.
func TestVLESSRealityNodeMetersVisionDirectCopy(t *testing.T) {
	certConfig := writeTestCert(t)
	cert, err := tls.LoadX509KeyPair(certConfig.CertFile, certConfig.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	node := startVLESSNode(t, nil)
	tlsConn, err := node.realityConn(t, "aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	client, err := vless.NewClient(snellTestUUID, vision, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialConn(tlsConn, M.ParseSocksaddr(l.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	inner := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	const size = 1 << 20
	go func() { _, _ = inner.Write(make([]byte, size)) }()
	if _, err := io.ReadFull(inner, make([]byte, size)); err != nil {
		t.Fatalf("echo through inner TLS: %v", err)
	}
	waitFor(t, "uid 42's inner TLS traffic to be reported", func() bool {
		up, down := node.fake.trafficFor(42)
		return up >= size && down >= size
	})
}

func TestVLESSRealityNodeVariants(t *testing.T) {
	echo := startEchoServer(t)
	localSettings := func(nodeInfo *api.NodeInfo, config *Config) {
		r := nodeInfo.REALITYConfig
		config.EnableREALITY = true
		config.REALITYConfigs = &REALITYConfig{Dest: r.Dest, ServerNames: r.ServerNames, PrivateKey: r.PrivateKey, ShortIds: []string{"0123"}}
	}
	for _, tc := range []struct {
		name    string
		change  func(*api.NodeInfo, *Config)
		shortID string
		flow    string
		// refused, when set, is a short id the node must not take.
		refused string
	}{
		{"no flow", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.VlessFlow = "" }, "aabbccdd", "", ""},
		{"empty short id", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.REALITYConfig.ShortIds = []string{""} }, "", vision, ""},
		// The legacy form of a VLESS node.
		{"V2ray with EnableVless", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.NodeType = "V2ray" }, "aabbccdd", vision, ""},
		// keeper sends REALITY settings only with tls 2; a local config
		// serves them otherwise, as on Xray.
		{"local settings", func(nodeInfo *api.NodeInfo, config *Config) {
			localSettings(nodeInfo, config)
			nodeInfo.EnableTLS, nodeInfo.EnableREALITY, nodeInfo.REALITYConfig = false, false, nil
		}, "0123", vision, ""},
		{"local settings win over the panel's", localSettings, "0123", vision, "aabbccdd"},
		{"DisableLocalREALITYConfig takes the panel's", func(nodeInfo *api.NodeInfo, config *Config) {
			localSettings(nodeInfo, config)
			config.DisableLocalREALITYConfig = true
		}, "aabbccdd", vision, "0123"},
		{"target by name", func(nodeInfo *api.NodeInfo, _ *Config) {
			_, port, _ := net.SplitHostPort(nodeInfo.REALITYConfig.Dest)
			nodeInfo.REALITYConfig.Dest = "localhost:" + port
		}, "aabbccdd", vision, ""},
		{"target by port", func(nodeInfo *api.NodeInfo, _ *Config) {
			_, port, _ := net.SplitHostPort(nodeInfo.REALITYConfig.Dest)
			nodeInfo.REALITYConfig.Dest = port
		}, "aabbccdd", vision, ""},
		// Xray's names for the same node.
		{"raw transport", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.TransportProtocol = "RAW" }, "aabbccdd", vision, ""},
		{"header type none", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.Header = []byte(`{"type":"None"}`) }, "aabbccdd", vision, ""},
		// Fields given up on sing-box only draw a warning.
		{"ignored fields", func(nodeInfo *api.NodeInfo, _ *Config) {
			r := nodeInfo.REALITYConfig
			r.ServerNames = append(r.ServerNames, "other.test")
			r.Show, r.MinClientVer, r.Mldsa65Seed = true, "1.8.0", "seed"
			r.LimitFallbackUpload = api.LimitFallback{AfterBytes: 1}
		}, "aabbccdd", vision, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := startVLESSNode(t, tc.change)
			if !node.proxies(t, tc.shortID, snellTestUUID, tc.flow, echo) {
				t.Fatal("uid 42 fails to proxy")
			}
			if tc.refused != "" && node.proxies(t, tc.refused, snellTestUUID, tc.flow, echo) {
				t.Fatalf("short id %s proxies", tc.refused)
			}
		})
	}
}

// A client closing its XUDP connection is a normal end, logged at debug. A
// REALITY probe stays an error: an unsuitable target fails real users with
// the same message.
func TestVLESSNodeLogsNormalEndsAtDebug(t *testing.T) {
	udpEcho := startUDPEchoServer(t)
	logPath := filepath.Join(t.TempDir(), "sing-box.log")
	node := startVLESSNodeLogging(t, SingBoxLog{Level: "debug", Path: logPath}, func(nodeInfo *api.NodeInfo, _ *Config) {
		nodeInfo.VlessFlow = ""
	})
	logLine := func(what string) string {
		var line string
		waitFor(t, what+" to be logged", func() bool {
			data, _ := os.ReadFile(logPath)
			for _, l := range strings.Split(string(data), "\n") {
				if strings.Contains(l, what) {
					line = l
					return true
				}
			}
			return false
		})
		return line
	}

	probe, err := tls.Dial("tcp", node.addr, &tls.Config{ServerName: "node.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("probe handshake: %v", err)
	}
	_ = probe.Close()
	if line := logLine("REALITY: processed invalid connection"); !strings.Contains(line, " ERROR ") {
		t.Errorf("the probe is not logged as an error: %s", line)
	}

	tlsConn, err := node.realityConn(t, "aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	client, err := vless.NewClient(snellTestUUID, "", logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := client.DialEarlyXUDPPacketConn(tlsConn, M.SocksaddrFromNet(udpEcho))
	if err != nil {
		t.Fatal(err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := packetConn.WriteTo([]byte("datagram"), udpEcho); err != nil {
		t.Fatal(err)
	}
	if _, _, err := packetConn.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatalf("UDP echo: %v", err)
	}
	_ = packetConn.Close()
	_ = tlsConn.Close()
	if line := logLine("mux connection closed"); !strings.Contains(line, " DEBUG ") {
		t.Errorf("the closed XUDP connection is not logged at debug: %s", line)
	}
}

func TestVLESSNodeRejectsUnsupportedSettings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*api.NodeInfo, *Config)
	}{
		// The base node starts, so the cases below fail for their change.
		{"reality", nil},
		{"VLESS without REALITY", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.EnableTLS, nodeInfo.EnableREALITY = true, false }},
		// panel.go keeps VMess on Xray until it goes; this guards the controller.
		{"VMess", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.NodeType, nodeInfo.EnableVless = "V2ray", false }},
		{"ws transport", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.TransportProtocol = "ws" }},
		{"http tcp header", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.Header = []byte(`{"type":"http","request":{}}`) }},
		{"tcp header without type", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.Header = []byte(`{"request":{}}`) }},
		{"unknown flow", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.VlessFlow = "xtls-rprx-direct" }},
		{"PROXY protocol to the target", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.REALITYConfig.ProxyProtocolVer = 1 }},
		// sing-box panics on this one.
		{"long short id", func(nodeInfo *api.NodeInfo, _ *Config) {
			nodeInfo.REALITYConfig.ShortIds = []string{strings.Repeat("a", 18)}
		}},
		{"odd short id", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.REALITYConfig.ShortIds = []string{"abc"} }},
		{"no short id", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.REALITYConfig.ShortIds = nil }},
		{"target without port", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.REALITYConfig.Dest = "node.test:" }},
		{"bad private key", func(nodeInfo *api.NodeInfo, _ *Config) { nodeInfo.REALITYConfig.PrivateKey = "short" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo := &api.NodeInfo{
				NodeType: "Vless", NodeID: 1, Port: uint32(freePort(t)), TransportProtocol: "tcp",
				EnableTLS: true, EnableVless: true, VlessFlow: vision, EnableREALITY: true,
				REALITYConfig: &api.REALITYConfig{
					Dest:        "127.0.0.1:443",
					ServerNames: []string{"node.test"},
					PrivateKey:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
					ShortIds:    []string{"aabb"},
				},
			}
			config := &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1, CertConfig: &mylego.CertConfig{CertMode: "none"}}
			if tc.change != nil {
				tc.change(nodeInfo, config)
			}
			c := NewTestSingBoxController(&fakeSnellAPI{
				nodeInfo: nodeInfo,
				users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID}},
			}, config)
			err := c.Start()
			if err == nil {
				_ = c.Close()
			}
			if started := err == nil; started != (tc.change == nil) {
				t.Fatalf("started = %v (%v)", started, err)
			}
		})
	}
}
