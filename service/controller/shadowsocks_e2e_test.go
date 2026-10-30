package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	shadowsocks "github.com/sagernet/sing-shadowsocks2"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/XrayR-project/XrayR/api"
	. "github.com/XrayR-project/XrayR/service/controller"
)

// ss2022KeySizes are the key sizes of the 2022 methods a node serves.
var ss2022KeySizes = map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32}

// ssServerKey is a server key of the size the method takes, as keeper hands
// out for 2022 methods.
func ssServerKey(method string) string {
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"[:ss2022KeySizes[method]]))
}

func startSSNode(t *testing.T, method string) (*fakeSnellAPI, *SingBoxController, string) {
	t.Helper()
	port := freePort(t)
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:          "Shadowsocks",
			NodeID:            1,
			Port:              uint32(port),
			TransportProtocol: "tcp",
			CypherMethod:      method,
			ServerKey:         ssServerKey(method),
		},
		users: []api.UserInfo{{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID, Email: snellTestUUID + "@v2board.user"}},
	}
	c := NewTestSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1})
	if err := c.Start(); err != nil {
		t.Fatalf("start Shadowsocks node: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return f, c, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// ssClient speaks for the user holding uuid, as a keeper subscription
// configures one, through the library the wkernel outbound uses.
func ssClient(t *testing.T, method, uuid string) shadowsocks.Method {
	t.Helper()
	password := uuid
	if keySize := ss2022KeySizes[method]; keySize > 0 {
		password = ssServerKey(method) + ":" + base64.StdEncoding.EncodeToString([]byte(uuid[:keySize]))
	}
	client, err := shadowsocks.CreateMethod(context.Background(), method, shadowsocks.MethodOptions{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func ssProxies(t *testing.T, nodeAddr, method, uuid, echo string) bool {
	t.Helper()
	tcpConn, err := net.Dial("tcp", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ssClient(t, method, uuid).DialConn(tcpConn, M.ParseSocksaddr(echo))
	if err != nil {
		_ = tcpConn.Close()
		return false
	}
	defer conn.Close()
	got, err := echoThrough(conn, "probe")
	return err == nil && got == "probe"
}

// ssUDPEchoes sends a datagram over native Shadowsocks UDP and waits for it
// back.
func ssUDPEchoes(t *testing.T, nodeAddr, method, uuid string, echo *net.UDPAddr) error {
	t.Helper()
	udpConn, err := net.Dial("udp", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	packetConn := ssClient(t, method, uuid).DialPacketConn(udpConn)
	defer packetConn.Close()
	_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := packetConn.WriteTo([]byte("datagram"), echo); err != nil {
		return err
	}
	// Room for the whole datagram: a short buffer truncates it, and the
	// client then fails to authenticate what is left.
	received := make([]byte, 2048)
	n, _, err := packetConn.ReadFrom(received)
	if err != nil {
		return err
	}
	if string(received[:n]) != "datagram" {
		return fmt.Errorf("echoed %q", received[:n])
	}
	return nil
}

func TestShadowsocks2022NodeProxiesAndMeters(t *testing.T) {
	const method = "2022-blake3-aes-256-gcm"
	echo := startEchoServer(t)
	udpEcho := startUDPEchoServer(t)
	f, c, nodeAddr := startSSNode(t, method)

	if !ssProxies(t, nodeAddr, method, snellTestUUID, echo) {
		t.Fatal("uid 42 fails to proxy TCP")
	}
	if ssProxies(t, nodeAddr, method, snellTestUUID2, echo) {
		t.Fatal("an unknown user key proxies")
	}
	if err := ssUDPEchoes(t, nodeAddr, method, snellTestUUID, udpEcho); err != nil {
		t.Fatalf("UDP: %v", err)
	}

	waitFor(t, "uid 42's traffic to be reported", func() bool {
		up, down := f.trafficFor(42)
		return up >= int64(len("probe")+len("datagram")) && down >= int64(len("probe")+len("datagram"))
	})

	// A user change replaces the users in place.
	generation := c.BoxGeneration()
	f.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID2, Passwd: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"}})
	waitFor(t, "uid 43 to be admitted", func() bool {
		return ssProxies(t, nodeAddr, method, snellTestUUID2, echo)
	})
	if ssProxies(t, nodeAddr, method, snellTestUUID, echo) {
		t.Error("removed uid 42 still proxies")
	}
	if c.BoxGeneration() != generation {
		t.Error("a user change rebuilt the box")
	}
}

func TestShadowsocksNodeServesEachMethod(t *testing.T) {
	echo := startEchoServer(t)
	udpEcho := startUDPEchoServer(t)
	for _, method := range []string{"2022-blake3-aes-128-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			_, _, nodeAddr := startSSNode(t, method)
			if !ssProxies(t, nodeAddr, method, snellTestUUID, echo) {
				t.Error("uid 42 fails to proxy TCP")
			}
			if err := ssUDPEchoes(t, nodeAddr, method, snellTestUUID, udpEcho); err != nil {
				t.Errorf("UDP: %v", err)
			}
		})
	}
}

// User updates land while connections authenticate against the users. An
// unlocked multi-user service crashes the process here ("concurrent map
// iteration and map write"); -race reports it every time.
func TestShadowsocksUserUpdatesWhileConnecting(t *testing.T) {
	echo := startEchoServer(t)
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			f, c, nodeAddr := startSSNode(t, method)
			client := ssClient(t, method, snellTestUUID)
			time.Sleep(time.Second) // PollPanel waits out UpdatePeriodic
			// A bounded number of dials, so the loop does not run out of local
			// ports; the updates keep going until the last one.
			dialed := make(chan struct{})
			go func() {
				defer close(dialed)
				for range 100 {
					tcpConn, err := net.Dial("tcp", nodeAddr)
					if err != nil {
						continue
					}
					if conn, err := client.DialConn(tcpConn, M.ParseSocksaddr(echo)); err == nil {
						// Waiting for the echo keeps the close off the server's first
						// write, which sing-shadowsocks races (docs/plans).
						_, _ = echoThrough(conn, "probe")
						_ = conn.Close()
					} else {
						_ = tcpConn.Close()
					}
				}
			}()
			uid42 := api.UserInfo{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID, Email: snellTestUUID + "@v2board.user"}
			uid43 := api.UserInfo{UID: 43, UUID: snellTestUUID2, Passwd: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"}
			generation := c.BoxGeneration()
		updates:
			for i := 0; ; i++ {
				select {
				case <-dialed:
					break updates
				default:
				}
				users := []api.UserInfo{uid42}
				if i%2 == 0 {
					users = append(users, uid43)
				}
				f.setUsers(users)
				if err := c.PollPanel(); err != nil {
					t.Fatal(err)
				}
			}
			if c.BoxGeneration() != generation {
				t.Error("user changes rebuilt the box")
			}
			if !ssProxies(t, nodeAddr, method, snellTestUUID, echo) {
				t.Error("uid 42 fails to proxy after the updates")
			}
		})
	}
}

// A rejected method change leaves the old box serving: its users keep the
// keys of the old method, and their open sessions survive the change and
// its revert.
func TestShadowsocksRejectedMethodChangeKeepsOldKeys(t *testing.T) {
	const method = "aes-128-gcm"
	echo := startEchoServer(t)
	f, c, nodeAddr := startSSNode(t, method)
	tcpConn, err := net.Dial("tcp", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	session, err := ssClient(t, method, snellTestUUID).DialConn(tcpConn, M.ParseSocksaddr(echo))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got, err := echoThrough(session, "probe"); err != nil || got != "probe" {
		t.Fatalf("open session: %q, %v", got, err)
	}
	generation := c.BoxGeneration()

	f.setNodeInfo(func(nodeInfo *api.NodeInfo) {
		nodeInfo.CypherMethod, nodeInfo.ServerKey = "2022-blake3-aes-128-gcm", ""
	})
	f.setUsers([]api.UserInfo{
		{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID, Email: snellTestUUID + "@v2board.user"},
		{UID: 43, UUID: snellTestUUID2, Passwd: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"},
	})
	waitFor(t, "uid 43 to be admitted", func() bool {
		return ssProxies(t, nodeAddr, method, snellTestUUID2, echo)
	})
	if got, err := echoThrough(session, "probe"); err != nil || got != "probe" {
		t.Errorf("the rejected change cut uid 42's session: %q, %v", got, err)
	}

	f.setNodeInfo(func(nodeInfo *api.NodeInfo) { nodeInfo.CypherMethod = method })
	time.Sleep(2 * time.Second) // a poll or two
	if got, err := echoThrough(session, "probe"); err != nil || got != "probe" {
		t.Errorf("the revert cut uid 42's session: %q, %v", got, err)
	}
	if c.BoxGeneration() != generation {
		t.Error("the rejected node info rebuilt the box")
	}
}

// A user the rejected node info skips still has their password change
// followed on the old box: sessions on the old password are cut.
func TestShadowsocksRejectedMethodChangeFollowsPasswords(t *testing.T) {
	const method = "aes-128-gcm"
	echo := startEchoServer(t)
	f, _, nodeAddr := startSSNode(t, method)
	tcpConn, err := net.Dial("tcp", nodeAddr)
	if err != nil {
		t.Fatal(err)
	}
	session, err := ssClient(t, method, snellTestUUID).DialConn(tcpConn, M.ParseSocksaddr(echo))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got, err := echoThrough(session, "probe"); err != nil || got != "probe" {
		t.Fatalf("open session: %q, %v", got, err)
	}

	// Too short for a 2022 key, so the new node info skips uid 42 and keeps
	// only uid 43.
	const newPassword = "short-password"
	f.setNodeInfo(func(nodeInfo *api.NodeInfo) {
		nodeInfo.CypherMethod, nodeInfo.ServerKey = "2022-blake3-aes-256-gcm", ""
	})
	f.setUsers([]api.UserInfo{
		{UID: 42, UUID: snellTestUUID, Passwd: newPassword, Email: snellTestUUID + "@v2board.user"},
		{UID: 43, UUID: snellTestUUID2, Passwd: snellTestUUID2, Email: snellTestUUID2 + "@v2board.user"},
	})
	waitFor(t, "the new password to be admitted", func() bool {
		return ssProxies(t, nodeAddr, method, newPassword, echo)
	})
	if got, err := echoThrough(session, "probe"); err == nil && got == "probe" {
		t.Error("a session on the old password still passes")
	}
}

func TestShadowsocksNodeRejectsUnsupportedSettings(t *testing.T) {
	obfs, _ := json.Marshal(map[string]any{"type": "http"})
	for _, tc := range []struct {
		name     string
		nodeInfo api.NodeInfo
	}{
		{"obfs http", api.NodeInfo{CypherMethod: "aes-128-gcm", Header: obfs}},
		{"2022 chacha20", api.NodeInfo{CypherMethod: "2022-blake3-chacha20-poly1305", ServerKey: ssServerKey("2022-blake3-aes-256-gcm")}},
		{"2022 without server key", api.NodeInfo{CypherMethod: "2022-blake3-aes-256-gcm"}},
		{"2022 server key of the wrong size", api.NodeInfo{CypherMethod: "2022-blake3-aes-128-gcm", ServerKey: ssServerKey("2022-blake3-aes-256-gcm")}},
		{"none", api.NodeInfo{CypherMethod: "none"}},
		{"stream cipher", api.NodeInfo{CypherMethod: "aes-256-cfb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo := tc.nodeInfo
			nodeInfo.NodeType, nodeInfo.NodeID, nodeInfo.Port = "Shadowsocks", 1, uint32(freePort(t))
			c := NewTestSingBoxController(&fakeSnellAPI{
				nodeInfo: &nodeInfo,
				users:    []api.UserInfo{{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID}},
			}, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1})
			if err := c.Start(); err == nil {
				_ = c.Close()
				t.Fatal("the node starts")
			}
		})
	}
}
