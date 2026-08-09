package discovery

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// DigPath reports the path to the dig binary if it's on PATH, and whether it
// was found at all — mirrors NmapPath/NetdiscoverPath, since dig-based
// reverse DNS is the same kind of "use it if it happens to be installed"
// enrichment those are, just for PTR lookups instead of port/ARP detail.
func DigPath() (string, bool) {
	p, err := exec.LookPath("dig")
	return p, err == nil
}

// ReverseDNSDig runs `dig -x ip` and returns the first PTR name it gets
// back, or "" if there wasn't one (NXDOMAIN, timeout, no PTR record, dig
// itself failing). +short strips dig's output down to just the answer
// (dot-terminated hostnames, one per line if there are several); the
// trailing dot is stripped to match reverseDNS()'s net.Resolver output.
// timeout bounds the whole subprocess rather than relying on dig's own
// +time flag, which only accepts whole seconds — the same
// exec.CommandContext pattern RunNmap/RunNetdiscover already use.
func ReverseDNSDig(ctx context.Context, path, ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-x", ip, "+short", "+time=1", "+tries=1")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return strings.TrimSuffix(line, ".")
	}
	return ""
}
