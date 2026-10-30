package controller_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	sbtls "github.com/sagernet/sing-box/common/tls"
	sboption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/XrayR-project/XrayR/api"
	. "github.com/XrayR-project/XrayR/service/controller"
)

// startHysteriaNode serves a Hysteria 2 node as keeper describes one: UDP
// with TLS, users keyed by password (the uuid).
func startHysteriaNode(t *testing.T, change func(*api.NodeInfo)) (*fakeSnellAPI, *SingBoxController, string) {
	t.Helper()
	port := freePort(t)
	nodeInfo := &api.NodeInfo{
		NodeType:          "Hysteria",
		NodeID:            1,
		Port:              uint32(port),
		TransportProtocol: "udp",
		EnableTLS:         true,
		HysteriaVersion:   2,
	}
	if change != nil {
		change(nodeInfo)
	}
	f := &fakeSnellAPI{
		nodeInfo: nodeInfo,
		users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID, Email: snellTestUUID + "@v2board.user"}},
	}
	c := NewTestSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1, CertConfig: writeTestCert(t)})
	if err := c.Start(); err != nil {
		t.Fatalf("start Hysteria node: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return f, c, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// hysteriaClient is the client the wkernel outbound runs, with its default
// ALPN h3.
func hysteriaClient(t *testing.T, nodeAddr, password, salamander string) *hysteria2.Client {
	t.Helper()
	ctx := context.Background()
	tlsConfig, err := sbtls.NewSTDClient(ctx, logger.NOP(), nodeAddr, sboption.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "node.test",
		Insecure:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:            ctx,
		Dialer:             N.SystemDialer,
		Logger:             logger.NOP(),
		ServerAddress:      M.ParseSocksaddr(nodeAddr),
		SalamanderPassword: salamander,
		Password:           password,
		TLSConfig:          tlsConfig,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(nil) })
	return client
}

func hysteriaProxies(t *testing.T, nodeAddr, password, salamander, echo string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := hysteriaClient(t, nodeAddr, password, salamander).DialConn(ctx, M.ParseSocksaddr(echo))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	got, err := echoThrough(conn, "probe")
	return err == nil && got == "probe"
}

func TestHysteria2NodeProxiesAndMeters(t *testing.T) {
	echo := startEchoServer(t)
	udpEcho := startUDPEchoServer(t)
	f, _, nodeAddr := startHysteriaNode(t, nil)

	if !hysteriaProxies(t, nodeAddr, snellTestUUID, "", echo) {
		t.Fatal("uid 42 fails to proxy TCP")
	}
	if hysteriaProxies(t, nodeAddr, "wrong-password", "", echo) {
		t.Fatal("a wrong password proxies")
	}

	packetConn, err := hysteriaClient(t, nodeAddr, snellTestUUID, "").ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := packetConn.WriteTo([]byte("datagram"), udpEcho); err != nil {
		t.Fatalf("send UDP: %v", err)
	}
	received := make([]byte, 2048)
	n, _, err := packetConn.ReadFrom(received)
	if err != nil || string(received[:n]) != "datagram" {
		t.Fatalf("UDP echo: %q, %v", received[:n], err)
	}

	waitFor(t, "uid 42's traffic to be reported", func() bool {
		up, down := f.trafficFor(42)
		return up >= int64(len("probe")+len("datagram")) && down >= int64(len("probe")+len("datagram"))
	})
}

// A user change replaces the users in place.
func TestHysteria2NodeReplacesUsers(t *testing.T) {
	if raceEnabled {
		t.Skip("sing-quic publishes its user map unsynchronized (docs/plans/sing-box-migration.md)")
	}
	echo := startEchoServer(t)
	f, c, nodeAddr := startHysteriaNode(t, nil)
	if !hysteriaProxies(t, nodeAddr, snellTestUUID, "", echo) {
		t.Fatal("uid 42 fails to proxy TCP")
	}
	generation := c.BoxGeneration()
	f.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID2, Passwd: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"}})
	waitFor(t, "uid 43 to be admitted", func() bool {
		return hysteriaProxies(t, nodeAddr, snellTestUUID2, "", echo)
	})
	if hysteriaProxies(t, nodeAddr, snellTestUUID, "", echo) {
		t.Error("removed uid 42 still proxies")
	}
	if c.BoxGeneration() != generation {
		t.Error("a user change rebuilt the box")
	}
}

// keeper's obfs is salamander, which wraps every packet: a client without
// the obfs password does not get through.
func TestHysteria2NodeServesSalamander(t *testing.T) {
	echo := startEchoServer(t)
	_, _, nodeAddr := startHysteriaNode(t, func(nodeInfo *api.NodeInfo) {
		nodeInfo.HysteriaObfs, nodeInfo.HysteriaObfsPassword = "salamander", "obfs-password"
	})
	if !hysteriaProxies(t, nodeAddr, snellTestUUID, "obfs-password", echo) {
		t.Fatal("uid 42 fails to proxy through salamander")
	}
	if hysteriaProxies(t, nodeAddr, snellTestUUID, "", echo) {
		t.Fatal("a client without obfs proxies")
	}
}

func TestHysteriaNodeRejectsUnsupportedSettings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*api.NodeInfo)
	}{
		// The base node info starts, so the cases below fail for their change.
		{"version 2", nil},
		// sing-box would start Hysteria 1 for these; Xray refused them.
		{"version 0", func(nodeInfo *api.NodeInfo) { nodeInfo.HysteriaVersion = 0 }},
		{"version 1", func(nodeInfo *api.NodeInfo) { nodeInfo.HysteriaVersion = 1 }},
		{"unknown obfs", func(nodeInfo *api.NodeInfo) { nodeInfo.HysteriaObfs, nodeInfo.HysteriaObfsPassword = "nope", "x" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo := api.NodeInfo{NodeType: "Hysteria", NodeID: 1, Port: uint32(freePort(t)), TransportProtocol: "udp", EnableTLS: true, HysteriaVersion: 2}
			if tc.change != nil {
				tc.change(&nodeInfo)
			}
			c := NewTestSingBoxController(&fakeSnellAPI{
				nodeInfo: &nodeInfo,
				users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID}},
			}, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1, CertConfig: writeTestCert(t)})
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
