package controller_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XrayR-project/XrayR/api"
	. "github.com/XrayR-project/XrayR/service/controller"
)

const snellTestUUID2 = "66666666-7777-8888-9999-000000000000"

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// startCountingEchoServer is an echo server that also counts what reaches
// it, so a test can tell whether a cut-off client's upload still gets through.
func startCountingEchoServer(t *testing.T) (addr string, received *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	received = new(atomic.Int64)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					received.Add(int64(n))
					if n > 0 {
						if _, err := c.Write(buf[:n]); err != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return l.Addr().String(), received
}

func echoThroughWithin(conn net.Conn, payload string, timeout time.Duration) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	go func() { _, _ = conn.Write([]byte(payload)) }()
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// proxies reports whether a client holding userKey gets a payload echoed.
func proxies(t *testing.T, nodeAddr, userKey, echo string) bool {
	t.Helper()
	conn, err := snellDial(t, nodeAddr, userKey, echo)
	if err != nil {
		return false
	}
	defer conn.Close()
	got, err := echoThrough(conn, "probe")
	return err == nil && got == "probe"
}

// Users come and go while the node keeps running: a user change replaces
// the inbound's users in place, a node info change rebuilds the box, and a
// node info the box rejects leaves the old one serving.
func TestSingBoxNodeFollowsPanelChanges(t *testing.T) {
	echo := startEchoServer(t)
	port := freePort(t)
	nodeAddr := fmt.Sprintf("127.0.0.1:%d", port)
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:       "Snell",
			NodeID:         1,
			Port:           uint32(port),
			SnellVersion:   6,
			SnellPSK:       snellTestPSK,
			SnellMultiUser: true,
		},
		users: []api.UserInfo{{UID: 42, UUID: snellTestUUID, Email: "a@test"}},
	}
	c := NewSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1}, "Keeper")
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// Its destination counts what arrives, to check the upload direction is
	// cut too: snell's Close only half-closes a connection that has replied.
	countingEcho, received := startCountingEchoServer(t)
	established, err := snellDial(t, nodeAddr, snellTestUUID, countingEcho)
	if err != nil {
		t.Fatalf("dial as uid 42: %v", err)
	}
	defer established.Close()
	if _, err := echoThrough(established, "before"); err != nil {
		t.Fatalf("proxy as uid 42: %v", err)
	}
	generation := c.BoxGeneration()

	// Swap uid 42 for uid 43.
	f.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID2, Email: "b@test"}})
	waitFor(t, "uid 43 to be admitted", func() bool {
		return proxies(t, nodeAddr, snellTestUUID2, echo)
	})
	if proxies(t, nodeAddr, snellTestUUID, echo) {
		t.Fatal("removed uid 42 can still open a new connection")
	}
	if c.BoxGeneration() != generation {
		t.Fatal("a user change rebuilt the box instead of updating users in place")
	}
	// A removed user is cut off at once, both ways, and what they used
	// before still reaches the panel.
	arrived := received.Load()
	_ = established.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = established.Write([]byte("after"))
	_, err = io.ReadFull(established, make([]byte, 1))
	// Give an upload that got through time to arrive.
	time.Sleep(500 * time.Millisecond)
	if err == nil {
		t.Fatal("removed uid 42 keeps its established connection")
	}
	if received.Load() != arrived {
		t.Fatal("removed uid 42's upload still reaches the destination")
	}
	waitFor(t, "uid 42's traffic to be reported after removal", func() bool {
		up, _ := f.trafficFor(42)
		return up >= int64(len("before"))
	})

	// A new uuid for uid 43 is a new credential: the session on the old one
	// is cut off, and the user stays on the box without a rebuild.
	const snellTestUUID3 = "77777777-8888-9999-0000-111111111111"
	onOldKey, err := snellDial(t, nodeAddr, snellTestUUID2, echo)
	if err != nil {
		t.Fatalf("dial as uid 43: %v", err)
	}
	defer onOldKey.Close()
	if _, err := echoThrough(onOldKey, "old key"); err != nil {
		t.Fatalf("proxy as uid 43: %v", err)
	}
	f.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID3, Email: "b@test"}})
	waitFor(t, "uid 43's new uuid to be admitted", func() bool {
		return proxies(t, nodeAddr, snellTestUUID3, echo)
	})
	if _, err := echoThrough(onOldKey, "still"); err == nil {
		t.Fatal("a session on uid 43's old uuid survived the change")
	}
	if proxies(t, nodeAddr, snellTestUUID2, echo) {
		t.Fatal("uid 43's old uuid still opens connections")
	}
	if c.BoxGeneration() != generation {
		t.Fatal("a uuid change rebuilt the box")
	}
	f.setUsers([]api.UserInfo{{UID: 43, UUID: snellTestUUID2, Email: "b@test"}})
	waitFor(t, "uid 43 back on its first uuid", func() bool {
		return proxies(t, nodeAddr, snellTestUUID2, echo)
	})

	// A node info sing-box refuses keeps the old box serving, and its users
	// still follow the panel meanwhile.
	f.setNodeInfo(func(n *api.NodeInfo) { n.SnellVersion = 5 })
	f.setUsers([]api.UserInfo{
		{UID: 43, UUID: snellTestUUID2, Email: "b@test"},
		{UID: 42, UUID: snellTestUUID, Email: "a@test"},
	})
	waitFor(t, "uid 42 to be admitted again while the node info is rejected", func() bool {
		return proxies(t, nodeAddr, snellTestUUID, echo)
	})
	if c.BoxGeneration() != generation {
		t.Fatal("an invalid node info replaced the running box")
	}
	if !proxies(t, nodeAddr, snellTestUUID2, echo) {
		t.Fatal("an invalid node info took the node down")
	}

	// A valid node info change rebuilds the box on the new port.
	newPort := freePort(t)
	newAddr := fmt.Sprintf("127.0.0.1:%d", newPort)
	f.setNodeInfo(func(n *api.NodeInfo) {
		n.SnellVersion = 6
		n.Port = uint32(newPort)
	})
	waitFor(t, "the node to move to the new port", func() bool {
		return proxies(t, newAddr, snellTestUUID2, echo)
	})
	if c.BoxGeneration() == generation {
		t.Fatal("a node info change did not rebuild the box")
	}
	if proxies(t, nodeAddr, snellTestUUID2, echo) {
		t.Fatal("the old port still serves after the rebuild")
	}

	// Removing every user stops the node admitting anyone; keeper reports
	// that as an error rather than an empty list.
	f.setUsers(nil)
	waitFor(t, "the last users to be shut out", func() bool {
		return !proxies(t, newAddr, snellTestUUID, echo) && !proxies(t, newAddr, snellTestUUID2, echo)
	})
	f.mu.Lock()
	repeated := f.repeatedUID
	f.mu.Unlock()
	if repeated {
		t.Fatal("a traffic report listed the same uid twice; keeper keeps only one of them")
	}
}

// A user with a long-lived connection stays online report after report, and
// a speed limit slows a user's traffic down while others run free.
func TestSingBoxNodeLimitsAndReportsOnline(t *testing.T) {
	echo := startEchoServer(t)
	port := freePort(t)
	nodeAddr := fmt.Sprintf("127.0.0.1:%d", port)
	const limit = 20000 // bytes per second
	f := &fakeSnellAPI{
		nodeInfo: &api.NodeInfo{
			NodeType:       "Snell",
			NodeID:         1,
			Port:           uint32(port),
			SnellVersion:   6,
			SnellPSK:       snellTestPSK,
			SnellMultiUser: true,
		},
		users: []api.UserInfo{
			{UID: 42, UUID: snellTestUUID, Email: "a@test", SpeedLimit: limit},
			{UID: 43, UUID: snellTestUUID2, Email: "b@test"},
		},
	}
	c := NewSingBoxController(f, &Config{ListenIP: "127.0.0.1", UpdatePeriodic: 1}, "Keeper")
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	payload := string(make([]byte, limit))
	timeEcho := func(userKey string) time.Duration {
		conn, err := snellDial(t, nodeAddr, userKey, echo)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		start := time.Now()
		if got, err := echoThroughWithin(conn, payload, 10*time.Second); err != nil || got != payload {
			t.Fatalf("echo %d bytes: %v", len(payload), err)
		}
		return time.Since(start)
	}
	// One burst is free, the other half of the round trip waits a second.
	if elapsed := timeEcho(snellTestUUID); elapsed < 800*time.Millisecond {
		t.Fatalf("a %d B/s user moved %d bytes both ways in %v", limit, len(payload), elapsed)
	}
	if elapsed := timeEcho(snellTestUUID2); elapsed > 500*time.Millisecond {
		t.Fatalf("an unlimited user took %v for the same", elapsed)
	}

	long, err := snellDial(t, nodeAddr, snellTestUUID2, echo)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer long.Close()
	if _, err := echoThrough(long, "hello"); err != nil {
		t.Fatalf("proxy: %v", err)
	}
	before := f.onlineReports(43)
	waitFor(t, "three more online reports listing uid 43", func() bool {
		return f.onlineReports(43) >= before+3
	})
}

// tlsReaches reports whether a TLS client naming serverName gets any byte to
// the echo server behind the node.
func tlsReaches(t *testing.T, nodeAddr, echo string, received *atomic.Int64, serverName string) bool {
	t.Helper()
	before := received.Load()
	conn, err := snellDial(t, nodeAddr, snellTestUUID, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// The echo server answers the ClientHello with itself, so the handshake
	// fails either way; what counts is whether the ClientHello got through.
	_ = tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	time.Sleep(200 * time.Millisecond)
	return received.Load() > before
}

// Audit rules match "tcp:host:port" like Xray, against both the dialed
// address and the sniffed domain, and stop applying once the panel drops them.
func TestSingBoxNodeAudits(t *testing.T) {
	panel, nodeAddr := startSnellNode(t, true)
	blockedIP, blockedReceived := startCountingEchoServer(t)
	open, openReceived := startCountingEchoServer(t)
	if !proxies(t, nodeAddr, snellTestUUID, blockedIP) {
		t.Fatal("the node does not proxy before any rule")
	}

	panel.setRules([]api.DetectRule{
		{ID: 1, Pattern: regexp.MustCompile("^tcp:" + regexp.QuoteMeta(blockedIP) + "$")},
		{ID: 2, Pattern: regexp.MustCompile(`blocked\.test`)},
	})
	waitFor(t, "the rule on the IP to apply", func() bool {
		return !proxies(t, nodeAddr, snellTestUUID, blockedIP)
	})
	if !proxies(t, nodeAddr, snellTestUUID, open) {
		t.Fatal("a destination no rule matches was rejected")
	}
	if tlsReaches(t, nodeAddr, open, openReceived, "blocked.test") {
		t.Fatal("a TLS connection to a blocked domain got through (sniffing off?)")
	}
	if !tlsReaches(t, nodeAddr, open, openReceived, "fine.test") {
		t.Fatal("a TLS connection to an allowed domain was rejected")
	}
	// sing dials the address, not the sniffed name, so an allowed SNI must
	// not carry a connection to a blocked address.
	if tlsReaches(t, nodeAddr, blockedIP, blockedReceived, "fine.test") {
		t.Fatal("an allowed SNI carried a connection to a blocked address")
	}

	panel.setRules(nil)
	waitFor(t, "the dropped rules to stop applying", func() bool {
		return proxies(t, nodeAddr, snellTestUUID, blockedIP)
	})
}
