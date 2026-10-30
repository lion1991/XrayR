package controller_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/trojan"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/common/mylego"
	. "github.com/XrayR-project/XrayR/service/controller"
)

// writeTestCert writes a self-signed certificate, as CertConfig's file mode
// reads one.
func writeTestCert(t *testing.T) *mylego.CertConfig {
	t.Helper()
	dir := t.TempDir()
	certConfig := &mylego.CertConfig{CertMode: "file", CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	writeCert(t, certConfig, 1)
	return certConfig
}

func writeCert(t *testing.T, certConfig *mylego.CertConfig, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "node.test"},
		DNSNames:     []string{"node.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certConfig.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certConfig.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// startTrojanNode serves a Trojan node as keeper describes one: TCP with
// TLS, users keyed by uuid with no password.
func startTrojanNode(t *testing.T, certConfig *mylego.CertConfig) (*fakeSnellAPI, *SingBoxController, string) {
	t.Helper()
	port := freePort(t)
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:          "Trojan",
			NodeID:            1,
			Port:              uint32(port),
			TransportProtocol: "tcp",
			EnableTLS:         true,
		},
		users: []api.UserInfo{{UID: 42, UUID: snellTestUUID, Email: snellTestUUID + "@v2board.user"}},
	}
	c := NewTestSingBoxController(f, &Config{
		ListenIP:       "127.0.0.1",
		UpdatePeriodic: 1,
		CertConfig:     certConfig,
	})
	if err := c.Start(); err != nil {
		t.Fatalf("start Trojan node: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return f, c, fmt.Sprintf("127.0.0.1:%d", port)
}

func trojanTLS(t *testing.T, nodeAddr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", nodeAddr, &tls.Config{
		ServerName:         "node.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatalf("TLS to node: %v", err)
	}
	return conn
}

// trojanProxies reports whether a client holding password gets a payload
// echoed over TCP.
func trojanProxies(t *testing.T, nodeAddr, password, echo string) bool {
	t.Helper()
	conn := trojan.NewClientConn(trojanTLS(t, nodeAddr), trojan.Key(password), M.ParseSocksaddr(echo))
	defer conn.Close()
	got, err := echoThrough(conn, "probe")
	return err == nil && got == "probe"
}

func TestTrojanNodeProxiesAndMeters(t *testing.T) {
	echo := startEchoServer(t)
	udpEcho := startUDPEchoServer(t)
	f, c, nodeAddr := startTrojanNode(t, writeTestCert(t))

	if !trojanProxies(t, nodeAddr, snellTestUUID, echo) {
		t.Fatal("uid 42 fails to proxy TCP")
	}
	if trojanProxies(t, nodeAddr, "wrong-password", echo) {
		t.Fatal("a wrong password proxies")
	}
	tlsConn := trojanTLS(t, nodeAddr)
	_ = tlsConn.Close()
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("ALPN %q, want h2 as Xray negotiates", got)
	}

	packetConn := trojan.NewClientPacketConn(trojanTLS(t, nodeAddr), trojan.Key(snellTestUUID))
	defer packetConn.Close()
	_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := packetConn.WriteTo([]byte("datagram"), udpEcho); err != nil {
		t.Fatalf("send UDP: %v", err)
	}
	received := make([]byte, 64)
	n, _, err := packetConn.ReadFrom(received)
	if err != nil || string(received[:n]) != "datagram" {
		t.Fatalf("UDP echo: %q, %v", received[:n], err)
	}

	waitFor(t, "uid 42's traffic to be reported", func() bool {
		up, down := f.trafficFor(42)
		return up >= int64(len("probe")+len("datagram")) && down >= int64(len("probe")+len("datagram"))
	})

	// A user change replaces the users in place.
	generation := c.BoxGeneration()
	f.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"}})
	waitFor(t, "uid 43 to be admitted", func() bool {
		return trojanProxies(t, nodeAddr, snellTestUUID2, echo)
	})
	if trojanProxies(t, nodeAddr, snellTestUUID, echo) {
		t.Error("removed uid 42 still proxies")
	}
	if c.BoxGeneration() != generation {
		t.Error("a user change rebuilt the box")
	}
}

func TestTrojanNodeRejectsUnsupportedSettings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nodeInfo api.NodeInfo
		config   Config
	}{
		{"websocket", api.NodeInfo{TransportProtocol: "ws", EnableTLS: true}, Config{}},
		{"panel REALITY", api.NodeInfo{TransportProtocol: "tcp", EnableREALITY: true}, Config{}},
		{"local REALITY", api.NodeInfo{TransportProtocol: "tcp", EnableTLS: true},
			Config{EnableREALITY: true, REALITYConfigs: &REALITYConfig{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo := tc.nodeInfo
			nodeInfo.NodeType, nodeInfo.NodeID, nodeInfo.Port = "Trojan", 1, uint32(freePort(t))
			config := tc.config
			config.ListenIP, config.UpdatePeriodic = "127.0.0.1", 1
			config.CertConfig = writeTestCert(t)
			c := NewTestSingBoxController(&fakeSnellAPI{
				nodeInfo: &nodeInfo,
				users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID}},
			}, &config)
			if err := c.Start(); err == nil {
				_ = c.Close()
				t.Fatal("the node starts")
			}
		})
	}
}

// A renewed certificate is served without rebuilding the box: certMonitor
// only rewrites the files.
func TestTrojanNodeReloadsCertificate(t *testing.T) {
	if os.Getenv("XRAYR_WKERNEL_TLS_RELOAD_FIX") == "" {
		// The pinned wkernel races its certificate and key reloads, so this
		// flakes until the dependency includes wkernel 65c53531.
		t.Skip("needs wkernel 65c53531; set XRAYR_WKERNEL_TLS_RELOAD_FIX=1 to run")
	}
	certConfig := writeTestCert(t)
	_, c, nodeAddr := startTrojanNode(t, certConfig)
	serial := func() int64 {
		conn := trojanTLS(t, nodeAddr)
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if got := serial(); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}

	generation := c.BoxGeneration()
	writeCert(t, certConfig, 2)
	waitFor(t, "the renewed certificate to be served", func() bool { return serial() == 2 })
	if c.BoxGeneration() != generation {
		t.Error("a renewed certificate rebuilt the box")
	}
}

// CertMode none serves plain Trojan, as Xray did, for a proxy in front that
// terminates TLS.
func TestTrojanNodeWithoutCertServesPlainTrojan(t *testing.T) {
	echo := startEchoServer(t)
	_, _, nodeAddr := startTrojanNode(t, &mylego.CertConfig{CertMode: "none"})
	tcpConn, err := net.Dial("tcp", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn := trojan.NewClientConn(tcpConn, trojan.Key(snellTestUUID), M.ParseSocksaddr(echo))
	defer conn.Close()
	if got, err := echoThrough(conn, "probe"); err != nil || got != "probe" {
		t.Fatalf("plain Trojan echo: %q, %v", got, err)
	}
}

// After a renewal only a QUIC node is rebuilt; the TCP ones reload in place.
func TestRenewalRebuildsOnlyQUICNodes(t *testing.T) {
	_, trojanNode, _ := startTrojanNode(t, writeTestCert(t))
	hysteriaNode := NewTestSingBoxController(&fakeSnellAPI{
		nodeInfo: &api.NodeInfo{NodeType: "Hysteria", NodeID: 1, Port: uint32(freePort(t)), EnableTLS: true, HysteriaVersion: 2},
		users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID}},
	}, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1, CertConfig: writeTestCert(t)})
	if err := hysteriaNode.Start(); err != nil {
		t.Fatalf("start Hysteria node: %v", err)
	}
	t.Cleanup(func() { _ = hysteriaNode.Close() })

	trojanGeneration, hysteriaGeneration := trojanNode.BoxGeneration(), hysteriaNode.BoxGeneration()
	trojanNode.ReloadQUICCertificate()
	hysteriaNode.ReloadQUICCertificate()
	if trojanNode.BoxGeneration() != trojanGeneration {
		t.Error("the Trojan node was rebuilt")
	}
	if hysteriaNode.BoxGeneration() != hysteriaGeneration+1 {
		t.Error("the Hysteria node was not rebuilt")
	}
}
