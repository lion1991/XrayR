package controller_test

import (
	"fmt"
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

	established, err := snellDial(t, nodeAddr, snellTestUUID, echo)
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
	// Disconnecting removed users is S3's job; until then the connection
	// lives on, and its traffic must still reach the panel.
	if _, err := echoThrough(established, "after"); err != nil {
		t.Fatalf("established connection broke on a user update: %v", err)
	}
	waitFor(t, "uid 42's traffic, including after removal, to be reported", func() bool {
		up, _ := f.trafficFor(42)
		return up >= int64(len("before")+len("after"))
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
