package controller

import (
	"testing"
	"time"
)

func TestResolveJitterPrecedence(t *testing.T) {
	cases := []struct {
		name               string
		panelSec, localSec int
		want               time.Duration
	}{
		{"panel wins over local", 30, 10, 30 * time.Second},
		{"panel unset falls back to local", 0, 10, 10 * time.Second},
		{"panel negative falls back to local", -1, 10, 10 * time.Second},
		{"both off -> disabled", 0, 0, 0},
		{"local only", 0, 45, 45 * time.Second},
		{"panel only", 20, 0, 20 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveJitter(tc.panelSec, tc.localSec); got != tc.want {
				t.Fatalf("resolveJitter(%d,%d) = %v, want %v", tc.panelSec, tc.localSec, got, tc.want)
			}
		})
	}
}

// withJitter must never sleep when jitter is disabled, and must run fn exactly
// once per call regardless.
func TestWithJitterDisabledRunsImmediately(t *testing.T) {
	var h jitterHolder // zero value => get()==0 => disabled
	calls := 0
	wrapped := withJitter(&h, func() error { calls++; return nil })

	start := time.Now()
	if err := wrapped(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("fn called %d times, want 1", calls)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("disabled jitter slept %v, want ~0", elapsed)
	}
}
