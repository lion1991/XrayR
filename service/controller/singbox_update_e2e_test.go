package controller_test

import (
	"fmt"
	"io"
	"net"
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
