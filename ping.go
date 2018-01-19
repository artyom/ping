package ping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
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
		pct = float64(s.Lost) / float64(s.Sent) * 100
	}
	return fmt.Sprintf("%d packets transmitted, %d packets received, %.1f%% packet loss\n"+
		"round-trip min/avg/max/stddev = %v/%v/%v/%v", s.Sent, s.Sent-s.Lost, pct,
		s.MinRTT.Truncate(time.Microsecond),
		s.AvgRTT.Truncate(time.Microsecond),
		s.MaxRTT.Truncate(time.Microsecond),
		s.DevRTT.Truncate(time.Microsecond),
	)
}

// ICMP pings addr using IPv4 ICMP echo messages until count packets are sent or
// ctx is canceled. If w is not null, output similar to ping(8) command is
// written there. If count is not positive, function runs until ctx is canceled.
// If addr is not an IPv4 address, it is resolved and first IPv4 record is used.
func ICMP(ctx context.Context, w io.Writer, count int, addr string) (*Summary, error) {
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
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	if w == nil {
		w = ioutil.Discard
	}

	rcvBuf := make([]byte, 1500)
	msgID := os.Getpid() & 0xffff // FIXME
	buf := make([]byte, payloadSize)
	_ = append(buf[:0], "ping"...)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var summary Summary
	var rttSum time.Duration
	// Welford's method: https://stackoverflow.com/a/897463/229034
	// https://www.johndcook.com/blog/standard_deviation/
	var m, s, k int64 = 0, 0, 1
sendLoop:
	for seq := 0; ; seq++ {
		if count > 0 && seq == count {
			break
		}
		var start time.Time
		switch seq {
		case 0:
			start = time.Now()
		default:
			select {
			case start = <-ticker.C:
			case <-ctx.Done():
				break sendLoop

			}
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
				fmt.Fprintln(w, "Request timeout for icmp_seq", seq) // FIXME
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
				{
					val := int64(rtt)
					_m := m
					m += (val - _m) / k
					s += (val - _m) * (val - m)
					k++
				}
				if summary.MaxRTT == 0 || summary.MaxRTT < rtt {
					summary.MaxRTT = rtt
				}
				if summary.MinRTT == 0 || summary.MinRTT > rtt {
					summary.MinRTT = rtt
				}
				rttSum += rtt
				summary.AvgRTT = rttSum / time.Duration(summary.Sent)
				fmt.Fprintf(w, "%d bytes from %s: icmp_seq=%d rtt=%v\n",
					n, remoteAddr.(*net.UDPAddr).IP,
					seq, rtt.Truncate(time.Microsecond))
				continue sendLoop
			}
		}
	}
	summary.DevRTT = time.Duration(int64(math.Sqrt(float64(s / (k - 1)))))

	fmt.Fprintf(w, "--- %s ping statistics ---\n", addr)
	fmt.Fprintln(w, summary.Stat())
	return &summary, nil
}

const payloadSize = 56
