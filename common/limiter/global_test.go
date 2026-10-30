package limiter

import "testing"

// A user at the limit keeps their devices and gets no more; the old check
// let one device too many in and then turned every device away.
func TestAddDevice(t *testing.T) {
	devices := map[string]int{"192.0.2.1": 7}
	if reject, added := addDevice(devices, "192.0.2.2", 7, 2); reject || !added {
		t.Fatal("rejected a device within the limit")
	}
	if reject, _ := addDevice(devices, "192.0.2.3", 7, 2); !reject {
		t.Fatal("admitted a third device over a limit of 2")
	}
	if reject, added := addDevice(devices, "192.0.2.1", 7, 2); reject || added {
		t.Fatal("a known device was rejected or added again at the limit")
	}
	if len(devices) != 2 {
		t.Fatalf("devices = %v, want the two admitted", devices)
	}
}
