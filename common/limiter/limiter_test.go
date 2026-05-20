package limiter

import (
	"fmt"
	"testing"

	"github.com/XrayR-project/XrayR/api"
)

// TestOnlineDeviceTracking reproduces the dispatcher → limiter → controller
// path that should populate UserOnlineIP and surface via GetOnlineDevice.
//
// Empirically the production node logs `Report 0 online users (limiter empty
// this tick)` even when Trojan traffic is flowing — meaning either the
// dispatcher never calls GetUserBucket (would still be a bug elsewhere) OR
// it does call it but UserOnlineIP fails to populate. This test isolates
// the second possibility.
func TestOnlineDeviceTracking(t *testing.T) {
	// Mirror production data shapes:
	//   - controller passes api.UserInfo.Email as the *raw* email
	//     (e.g. "abc@v2board.user") via AddInboundLimiter; the limiter then
	//     builds its UserInfo lookup key as `<tag>|<rawEmail>|<UID>`.
	//   - xray-core's userbuilder rewrites protocol.User.Email = buildUserTag
	//     = `<tag>|<rawEmail>|<UID>`. That's the string the dispatcher hands
	//     to GetUserBucket as the email argument.
	// So the dispatcher's email arg should equal the limiter's UserInfo
	// key — confirm that GetUserBucket finds the UserInfo and that
	// UserOnlineIP gets populated with the right UID.
	l := New()
	tag := "Trojan_0.0.0.0_53300"
	rawEmail := "abc@v2board.user"
	dispatcherEmail := fmt.Sprintf("%s|%s|%d", tag, rawEmail, 1) // buildUserTag
	ip := "1.2.3.4"

	users := []api.UserInfo{{UID: 1, Email: rawEmail, SpeedLimit: 0, DeviceLimit: 0}}
	if err := l.AddInboundLimiter(tag, 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter: %v", err)
	}

	_, _, reject := l.GetUserBucket(tag, dispatcherEmail, ip)
	if reject {
		t.Fatalf("GetUserBucket rejected unexpectedly")
	}

	devices, err := l.GetOnlineDevice(tag)
	if err != nil {
		t.Fatalf("GetOnlineDevice: %v", err)
	}
	if devices == nil {
		t.Fatalf("GetOnlineDevice returned nil slice")
	}
	if len(*devices) != 1 {
		t.Fatalf("expected 1 online device, got %d: %#v", len(*devices), *devices)
	}
	if (*devices)[0].UID != 1 || (*devices)[0].IP != ip {
		t.Fatalf("unexpected device entry: %+v — UID mismatch means limiter's "+
			"UserInfo.Load(dispatcherEmail) failed to find the registered user", (*devices)[0])
	}
}

// TestOnlineDeviceTrackingTagMismatch documents what happens when the
// dispatcher's sessionInbound.Tag is a different string than what the
// controller registered via AddInboundLimiter. This is the leading
// hypothesis for the device-count=0 bug on the production node.
func TestOnlineDeviceTrackingTagMismatch(t *testing.T) {
	l := New()
	registeredTag := "Trojan_0.0.0.0_53300"
	dispatcherTag := "Trojan_443" // pretend the dispatcher hands a different string
	email := fmt.Sprintf("%s|%s|%d", registeredTag, "abc@v2board.user", 1)
	ip := "1.2.3.4"

	users := []api.UserInfo{{UID: 1, Email: email}}
	if err := l.AddInboundLimiter(registeredTag, 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter: %v", err)
	}

	// Dispatcher calls with the mismatched tag.
	_, _, _ = l.GetUserBucket(dispatcherTag, email, ip)

	// GetOnlineDevice on the registered tag should now return empty —
	// reproducing the production symptom exactly.
	devices, err := l.GetOnlineDevice(registeredTag)
	if err != nil {
		t.Fatalf("GetOnlineDevice: %v", err)
	}
	if len(*devices) != 0 {
		t.Fatalf("expected 0 devices on tag mismatch, got %d", len(*devices))
	}
}

// TestOnlineDeviceConsumedByGetOnlineDevice verifies that GetOnlineDevice
// clears UserOnlineIP. This is the existing behavior, and ensures that
// devices reported one tick are not reported again next tick unless a
// fresh GetUserBucket call repopulates them.
func TestOnlineDeviceConsumedByGetOnlineDevice(t *testing.T) {
	l := New()
	tag := "Trojan_0.0.0.0_53300"
	email := fmt.Sprintf("%s|%s|%d", tag, "abc@v2board.user", 1)

	users := []api.UserInfo{{UID: 1, Email: email}}
	if err := l.AddInboundLimiter(tag, 0, &users, nil); err != nil {
		t.Fatalf("AddInboundLimiter: %v", err)
	}

	l.GetUserBucket(tag, email, "1.2.3.4")

	devices, _ := l.GetOnlineDevice(tag)
	if len(*devices) != 1 {
		t.Fatalf("first GetOnlineDevice: expected 1, got %d", len(*devices))
	}

	// Second call without a fresh connection should be empty.
	devices, _ = l.GetOnlineDevice(tag)
	if len(*devices) != 0 {
		t.Fatalf("second GetOnlineDevice without new conn: expected 0, got %d", len(*devices))
	}
}
