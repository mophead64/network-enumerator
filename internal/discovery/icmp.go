package discovery

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMPPinger sends ICMP echo requests over a single shared socket and
// dispatches replies to whichever goroutine is waiting on the matching
// sequence number. A single socket is used (rather than one per ping)
// because raw ICMP sockets are a limited, privileged resource.
//
// A raw ICMP socket bound to 0.0.0.0 receives every ICMP packet arriving on
// the interface, not just replies to our own requests — other processes'
// pings, a router's health checks, or (as observed running this under
// Rancher Desktop's virtualized networking) copies of unrelated echo
// traffic from elsewhere on the broadcast domain. Matching a reply to a
// pending ping purely by source IP is therefore not safe: any of that
// ambient traffic from an IP we happen to have a ping in flight to gets
// misread as "that host is alive". Replies are matched by echo ID+sequence
// (unique per outstanding ping) with the source IP double-checked as a
// second factor, so only genuine replies to our own requests count.
//
// It prefers a privileged raw socket (works when the process has
// CAP_NET_RAW, e.g. running as root or in the container's default Docker
// capability set) and transparently falls back to an unprivileged
// datagram-oriented ICMP socket where the OS supports one. If neither is
// available (e.g. unprivileged on Linux without ping_group_range
// configured), NewICMPPinger reports ok=false and callers should rely on
// TCP-based discovery alone.
type ICMPPinger struct {
	conn     *icmp.PacketConn
	usingUDP bool
	id       int
	seq      uint32

	mu      sync.Mutex
	waiters map[int]pendingPing
}

type pendingPing struct {
	ip string
	ch chan struct{}
}

func NewICMPPinger() (*ICMPPinger, bool) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	usingUDP := false
	if err != nil {
		conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
		usingUDP = true
		if err != nil {
			return nil, false
		}
	}
	p := &ICMPPinger{
		conn:     conn,
		usingUDP: usingUDP,
		id:       os.Getpid() & 0xffff,
		waiters:  make(map[int]pendingPing),
	}
	go p.readLoop()
	return p, true
}

func (p *ICMPPinger) Close() {
	p.conn.Close()
}

func (p *ICMPPinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, peer, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		msg, err := icmp.ParseMessage(1, buf[:n]) // 1 = ICMPv4 protocol number
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// On a raw socket we fully control the ID field end-to-end, so a
		// mismatch means the packet isn't one of ours. On the unprivileged
		// udp4 fallback, the kernel substitutes its own ID for demuxing
		// (see man 7 icmp, ping_group_range) — it already only delivers
		// genuine replies to this socket, so ID isn't ours to check there.
		if !p.usingUDP && echo.ID != p.id {
			continue
		}

		p.mu.Lock()
		pending, ok := p.waiters[echo.Seq]
		p.mu.Unlock()
		if !ok || pending.ip != peerIP(peer) {
			continue // stale/unrelated sequence number, or wrong source
		}
		select {
		case pending.ch <- struct{}{}:
		default:
		}
	}
}

func peerIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		return addr.String()
	}
}

// Ping sends one echo request to ip and waits up to timeout for a reply.
func (p *ICMPPinger) Ping(ip string, timeout time.Duration) bool {
	seq := int(atomic.AddUint32(&p.seq, 1) & 0xffff)
	ch := make(chan struct{}, 1)

	p.mu.Lock()
	p.waiters[seq] = pendingPing{ip: ip, ch: ch}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, seq)
		p.mu.Unlock()
	}()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: p.id, Seq: seq, Data: []byte("net-enumerator")},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return false
	}

	var writeErr error
	if p.usingUDP {
		_, writeErr = p.conn.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP(ip)})
	} else {
		_, writeErr = p.conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ip)})
	}
	if writeErr != nil {
		return false
	}

	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}
