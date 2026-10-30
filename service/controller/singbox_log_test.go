package controller

import (
	"errors"
	"io"
	"testing"

	"github.com/sagernet/quic-go"
	sblog "github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// The errors are wrapped as sing-box logs them.
func TestDemoteNormalEnds(t *testing.T) {
	inbound := func(err error) error { return E.Cause(err, "process connection from 1.2.3.4:5") }
	stream := func(code quic.StreamErrorCode, remote bool) error {
		return &quic.StreamError{StreamID: 112, ErrorCode: code, Remote: remote}
	}
	mux := func(err error) error {
		return inbound(E.Cause(E.Cause(err, "read frame header"), "mux connection closed"))
	}
	reality := func(message string) error { return inbound(E.Cause(errors.New(message), "TLS handshake")) }
	for _, tc := range []struct {
		name   string
		err    error
		normal bool
	}{
		{"hysteria2 stream dropped by the client", E.Cause(stream(0, true), "report handshake success"), true},
		{"hysteria2 stream reset with a code", E.Cause(stream(1, true), "report handshake success"), false},
		{"hysteria2 stream dropped by the node", E.Cause(stream(0, false), "report handshake success"), false},
		{"hysteria2 stream dropped elsewhere", E.Cause(stream(0, true), "read request"), false},
		{"mux closed between frames", mux(io.EOF), true},
		{"mux frame cut off", mux(io.ErrUnexpectedEOF), false},
		{"connection closed before its header", inbound(io.EOF), false},
		{"REALITY probe or unsuitable target", reality("REALITY: processed invalid connection"), false},
		{"REALITY target unreachable", reality("REALITY: failed to dial dest"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := sblog.LevelError
			if tc.normal {
				want = sblog.LevelDebug
			}
			if got := demoteNormalEnds(sblog.LevelError, []any{tc.err}); got != want {
				t.Errorf("level %v, want %v", got, want)
			}
			if got := demoteNormalEnds(sblog.LevelWarn, []any{tc.err}); got != sblog.LevelWarn {
				t.Errorf("a warning becomes %v", got)
			}
		})
	}
}
