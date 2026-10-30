package controller

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/time/rate"
)

// rateConn takes tokens for every byte the user sends or receives. It shows
// its upstream for casts (handshake reporting) but is not replaceable, so
// sing's copy cannot unwrap it and bypass the limit.
type rateConn struct {
	net.Conn
	bucket *rate.Limiter
}

func (c *rateConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	waitTokens(c.bucket, n)
	return n, err
}

func (c *rateConn) Write(p []byte) (int, error) {
	waitTokens(c.bucket, len(p))
	return c.Conn.Write(p)
}

// CloseWrite keeps the half-close the copy would do without the wrapper
// (snell v5 tells the client why the target closed). Like the copy, it looks
// past the traffic counter, which sits right below.
func (c *rateConn) CloseWrite() error {
	writer, _ := N.UnwrapCountWriter(c.Conn, nil)
	if closer, ok := N.UnwrapWriter(writer).(N.WriteCloser); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *rateConn) Upstream() any {
	return c.Conn
}

type ratePacketConn struct {
	N.PacketConn
	bucket *rate.Limiter
}

func (c *ratePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		waitTokens(c.bucket, buffer.Len())
	}
	return destination, err
}

func (c *ratePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	waitTokens(c.bucket, buffer.Len())
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *ratePacketConn) Upstream() any {
	return c.PacketConn
}

// waitTokens waits in burst-sized steps: WaitN refuses more than one burst
// at once and would let the whole read through unlimited.
func waitTokens(bucket *rate.Limiter, n int) {
	for n > 0 {
		step := min(n, bucket.Burst())
		if step <= 0 {
			// Unlimited (rate.Inf) or a broken bucket: nothing to wait for.
			return
		}
		if bucket.WaitN(context.Background(), step) != nil {
			return
		}
		n -= step
	}
}
