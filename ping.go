package ping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Summary holds statistics from a single ping run
type Summary struct {
	Sent, Lost int
	MinRTT     time.Duration
	AvgRTT     time.Duration
	MaxRTT     time.Duration
	DevRTT     time.Duration
}

func (s Summary) Stat() string {
	var pct float64
	if s.Sent > 0 && s.Lost > 0 {
		pct = float64(s.Lost) / float64(s.Sent)
	}
	return fmt.Sprintf("%d packets transmitted, %d packets received, %.1f%% packet loss\n"+
		"round-trip min/avg/max/stddev = %v/%v/%v/%v", s.Sent, s.Sent-s.Lost, pct,
		s.MinRTT.Truncate(time.Microsecond),
		s.AvgRTT.Truncate(time.Microsecond),
		s.MaxRTT.Truncate(time.Microsecond),
		s.DevRTT.Truncate(time.Microsecond),
	)
}

func ICMP(ctx context.Context, count int, addr string) (*Summary, error) {
	if count <= 0 {
		return nil, errors.New("count should be positive")
	}
	dst := net.ParseIP(addr)
	if dst == nil {
		ips, err := net.LookupIP(addr)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				dst = ip
				break
			}
		}
	}
	if dst == nil {
		return nil, errors.New("cannot resolve address to ipv4")
	}
	dstAddr := &net.UDPAddr{IP: dst}

	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	defer c.Close()

	rcvBuf := make([]byte, 1500)
	msgID := os.Getpid() & 0xffff
	buf := make([]byte, payloadSize)
	_ = append(buf[:0], "ping"...)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var summary Summary
	var rttSum time.Duration
sendLoop:
	for seq := 0; seq < count; seq++ {
		var start time.Time
		switch seq {
		case 0:
			start = time.Now()
		default:
			start = <-ticker.C
		}
		binary.LittleEndian.PutUint64(buf[3:], uint64(start.UnixNano()))
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Body: &icmp.Echo{ID: msgID, Seq: seq, Data: buf},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			return nil, err
		}
		sendTime := time.Now()
		if _, err := c.WriteTo(b, dstAddr); err != nil {
			return nil, err
		}
		summary.Sent++
		if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return nil, err
		}

		for {
			n, remoteAddr, err := c.ReadFrom(rcvBuf)
			if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
				fmt.Println("Request timeout for icmp_seq", seq) // FIXME
				summary.Lost++
				continue sendLoop
			}
			if err != nil {
				return nil, err
			}
			rtt := time.Since(sendTime)
			msg2, err := icmp.ParseMessage(1, rcvBuf[:n])
			if err != nil {
				continue
			}
			if msg2.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			if body, ok := msg2.Body.(*icmp.Echo); ok &&
				body.ID == msgID &&
				body.Seq == seq &&
				bytes.Equal(body.Data, buf) {
				rttSum += rtt
				if summary.MaxRTT == 0 || summary.MaxRTT < rtt {
					summary.MaxRTT = rtt
				}
				if summary.MinRTT == 0 || summary.MinRTT > rtt {
					summary.MinRTT = rtt
				}
				summary.AvgRTT = rttSum / time.Duration(summary.Sent)
				fmt.Printf("%d bytes from %s: icmp_seq=%d rtt=%v\n",
					n, remoteAddr.(*net.UDPAddr).IP,
					seq, rtt.Truncate(time.Microsecond))
				continue sendLoop
			}
		}
	}
	return &summary, nil
}

const payloadSize = 56

var emptyBuf [payloadSize]byte // used to wipe payload buffers
