package controller_test

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/XrayR-project/XrayR/api"
	. "github.com/XrayR-project/XrayR/service/controller"
)

// v6 rejects a psk outside 12..255 bytes, mirroring snell-server's own check.
const snellTestPSK = "0123456789abcdef"

const snellTestUUID = "11111111-2222-3333-4444-555555555555"

// fakeSnellAPI is a panel stand-in: it hands the controller a Snell node plus
// one user, and records whatever traffic gets pushed back.
type fakeSnellAPI struct {
	nodeInfo *api.NodeInfo
	users    []api.UserInfo

	mu       sync.Mutex
	reported []api.UserTraffic
}

func (f *fakeSnellAPI) GetNodeInfo() (*api.NodeInfo, error) { return f.nodeInfo, nil }

func (f *fakeSnellAPI) GetUserList() (*[]api.UserInfo, error) {
	users := f.users
	return &users, nil
}

func (f *fakeSnellAPI) ReportUserTraffic(traffic *[]api.UserTraffic) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reported = append(f.reported, *traffic...)
	return nil
}

func (f *fakeSnellAPI) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: "fake", NodeID: 1, NodeType: f.nodeInfo.NodeType}
}

func (f *fakeSnellAPI) ReportNodeStatus(*api.NodeStatus) error        { return nil }
func (f *fakeSnellAPI) ReportNodeOnlineUsers(*[]api.OnlineUser) error { return nil }
func (f *fakeSnellAPI) GetNodeRule() (*[]api.DetectRule, error)       { return &[]api.DetectRule{}, nil }
func (f *fakeSnellAPI) ReportIllegal(*[]api.DetectResult) error       { return nil }
func (f *fakeSnellAPI) Debug()                                        {}

// trafficFor sums everything the controller has pushed for a uid so far.
func (f *fakeSnellAPI) trafficFor(uid int) (up, down int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.reported {
		if t.UID == uid {
			up += t.Upload
			down += t.Download
		}
	}
	return up, down
}

func (f *fakeSnellAPI) reportCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reported)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startEchoServer is the origin the proxied connection is routed to, so the
// test exercises the whole path: snell handshake -> box router -> direct
// outbound -> destination, and back.
func startEchoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return l.Addr().String()
}

// startSnellNode boots a real SingBoxController against the fake panel.
func startSnellNode(t *testing.T, multiUser bool) (*fakeSnellAPI, string) {
	t.Helper()
	port := freePort(t)
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:          "Snell",
			NodeID:            1,
			Port:              uint32(port),
			TransportProtocol: "tcp",
			SnellVersion:      6,
			SnellPSK:          snellTestPSK,
			SnellMode:         "default",
			SnellMultiUser:    multiUser,
		},
		users: []api.UserInfo{{
			UID:    42,
			UUID:   snellTestUUID,
			Passwd: snellTestUUID,
			Email:  snellTestUUID + "@v2board.user",
		}},
	}

	c := NewSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1}, "Keeper")
	if err := c.Start(); err != nil {
		t.Fatalf("SingBoxController.Start with a Snell node: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return f, fmt.Sprintf("127.0.0.1:%d", port)
}

// snellDial performs a real Snell v6 handshake against the node. An empty
// userKey reproduces what the official Surge client sends: no client-id.
func snellDial(t *testing.T, nodeAddr, userKey, dest string) (net.Conn, error) {
	t.Helper()
	var key []byte
	if userKey != "" {
		key = []byte(userKey)
	}
	client, err := snellv6.NewClient(snellv6.ClientOptions{
		PSK:     []byte(snellTestPSK),
		UserKey: key,
		Mode:    snellv6.ModeDefault,
	})
	if err != nil {
		return nil, err
	}
	raw, err := net.Dial("tcp", nodeAddr)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialConn(raw, M.ParseSocksaddr(dest))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// echoThrough proves the tunnel actually carries payload both ways. The Snell
// request is written lazily, so an auth failure surfaces here, on the read.
func echoThrough(conn net.Conn, payload string) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// TestSnellV6MultiUserMetersTrafficAndRejectsSurge pins down the multi_user
// half of the trade-off: per-user keys make the node meterable, and that is
// exactly what locks the official Surge client out — Snell carries the user key
// in the request's ClientID field, and Surge has no option to set one.
func TestSnellV6MultiUserMetersTrafficAndRejectsSurge(t *testing.T) {
	echo := startEchoServer(t)
	panel, nodeAddr := startSnellNode(t, true)

	// A client holding the user's key proxies end to end.
	conn, err := snellDial(t, nodeAddr, snellTestUUID, echo)
	if err != nil {
		t.Fatalf("dial with a valid user key: %v", err)
	}
	defer conn.Close()
	got, err := echoThrough(conn, "hello-snell")
	if err != nil {
		t.Fatalf("proxy a payload with a valid user key: %v", err)
	}
	if got != "hello-snell" {
		t.Fatalf("echo mismatch through the tunnel: got %q", got)
	}

	// What official Surge sends: psk only, no client-id.
	surge, surgeErr := snellDial(t, nodeAddr, "", echo)
	if surgeErr == nil {
		_, surgeErr = echoThrough(surge, "hello-surge")
		_ = surge.Close()
	}
	if surgeErr == nil {
		t.Fatal("a multi_user node accepted a client that sent no client-id: official Surge would connect here, which contradicts the trade-off this mode is documented on")
	}
	t.Logf("OK: no-client-id client (i.e. official Surge) rejected in multi_user mode: %v", surgeErr)

	// The point of multi_user: the panel gets per-user numbers.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if up, down := panel.trafficFor(42); up > 0 && down > 0 {
			t.Logf("OK: traffic attributed to UID 42 and pushed to the panel: up=%d down=%d", up, down)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("multi_user node never reported per-user traffic for UID 42")
}

// TestSnellV6SharedPSKServesSurgeButCannotMeter pins down the other half: drop
// the per-user keys and the official Surge client connects — but nobody is
// identified, so the node cannot bill anyone. This asserts the limitation on
// purpose, so that a future change which starts reporting traffic here (or
// starts rejecting Surge) has to come and explain itself.
func TestSnellV6SharedPSKServesSurgeButCannotMeter(t *testing.T) {
	echo := startEchoServer(t)
	panel, nodeAddr := startSnellNode(t, false)

	// Surge-shaped client: psk only, no client-id. Must work.
	conn, err := snellDial(t, nodeAddr, "", echo)
	if err != nil {
		t.Fatalf("shared-psk node rejected a client with no client-id, so official Surge could not connect: %v", err)
	}
	defer conn.Close()
	got, err := echoThrough(conn, "hello-surge")
	if err != nil {
		t.Fatalf("shared-psk node failed to proxy a Surge-shaped client: %v", err)
	}
	if got != "hello-surge" {
		t.Fatalf("echo mismatch through the tunnel: got %q", got)
	}
	t.Log("OK: Surge-shaped client (psk only, no client-id) proxies fine in shared-psk mode")

	// Nothing can be attributed: no user identity ever reaches the tracker.
	// Give the 1s traffic task several cycles to prove it stays silent.
	time.Sleep(4 * time.Second)
	if n := panel.reportCount(); n != 0 {
		up, down := panel.trafficFor(42)
		t.Fatalf("shared-psk node pushed %d traffic record(s) (uid42 up=%d down=%d), but no client is identifiable in this mode — the numbers cannot be real", n, up, down)
	}
	t.Log("OK: shared-psk node reports no per-user traffic — unmetered by construction, as documented")
}

// v5 + multi_user is unreachable by construction: Surge speaks v5 but cannot
// send a client-id, and the clients that can (sing-box family) implement no v5
// client at all — sing-snell ships snellv5/server.go with no client.go. Booting
// such a node would look healthy and serve nobody, so it must fail loudly.
func TestSnellV5MultiUserIsRefused(t *testing.T) {
	port := freePort(t)
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:       "Snell",
			NodeID:         1,
			Port:           uint32(port),
			SnellVersion:   5,
			SnellPSK:       "psk-for-v5",
			SnellMultiUser: true,
		},
		users: []api.UserInfo{{UID: 42, UUID: snellTestUUID, Passwd: snellTestUUID}},
	}

	c := NewSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1}, "Keeper")
	err := c.Start()
	if err == nil {
		_ = c.Close()
		t.Fatal("a v5 multi_user Snell node started, but no client on earth can connect to it")
	}
	t.Logf("OK: refused to boot an unreachable v5 multi_user node: %v", err)
}

// A multi_user node with zero users must refuse to boot: sing-box picks the
// service implementation off len(Users), so an empty list silently builds the
// SHARED-PSK service — any psk holder connects and nobody is metered, the
// exact inverse of what the operator asked for. keeper cannot normally produce
// this (its GetUserList errors on an empty list), so this pins the invariant
// locally against that ever being relaxed.
func TestSnellV6MultiUserWithZeroUsersIsRefused(t *testing.T) {
	port := freePort(t)
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:       "Snell",
			NodeID:         1,
			Port:           uint32(port),
			SnellVersion:   6,
			SnellPSK:       snellTestPSK,
			SnellMultiUser: true,
		},
		users: []api.UserInfo{},
	}

	c := NewSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1}, "Keeper")
	err := c.Start()
	if err == nil {
		_ = c.Close()
		t.Fatal("a multi_user Snell node with zero users started — it would be running in shared-psk mode against the operator's explicit intent")
	}
	t.Logf("OK: refused to boot a zero-user multi_user node: %v", err)
}
