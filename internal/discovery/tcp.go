package discovery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeTCP attempts a TCP connect to host:port. It returns open=true only
// for a completed handshake. A connection actively refused still proves the
// host is alive (refused=true) even though the port itself is closed.
func ProbeTCP(host string, port int, timeout time.Duration) (open, refused bool) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return false, true
		}
		return false, false
	}
	conn.Close()
	return true, false
}

// GrabBanner opens a short-lived connection to host:port and returns
// whatever the service sends first (or, for known text protocols, what it
// sends in response to a minimal probe). Best-effort only: many services
// won't say anything without a specific handshake, and that's fine.
func GrabBanner(host string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp4", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	switch port {
	case 80, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000, 81:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	case 443, 8443:
		// Skip TLS handshake complexity for a lightweight banner grab.
		return ""
	}

	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}
