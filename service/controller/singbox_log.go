package controller

import (
	"errors"
	"io"
	"strings"

	"github.com/sagernet/quic-go"
	sblog "github.com/sagernet/sing-box/log"
)

// demoteNormalEnds logs at debug the errors sing-box reports when a peer ends
// a connection normally, so they do not bury real errors. Xray did not log
// these as errors either.
func demoteNormalEnds(level sblog.Level, args []any) sblog.Level {
	if level != sblog.LevelError {
		return level
	}
	for _, arg := range args {
		if err, ok := arg.(error); ok && isNormalEnd(err) {
			return sblog.LevelDebug
		}
	}
	return level
}

func isNormalEnd(err error) bool {
	message := err.Error()
	// A Hysteria 2 client dropped a stream before the node answered it, as
	// browsers do with the spare connections they race.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) && streamErr.Remote && streamErr.ErrorCode == 0 {
		return strings.Contains(message, "report handshake success")
	}
	// A VLESS client closed its mux (XUDP) connection between frames; a
	// frame cut off midway ends in io.ErrUnexpectedEOF instead.
	//
	// REALITY's "processed invalid connection" is not demoted: besides
	// probes, every user gets it when the target's handshake does not suit
	// REALITY, and the message does not tell the two apart.
	return errors.Is(err, io.EOF) && strings.HasSuffix(message, "mux connection closed: read frame header: EOF")
}
