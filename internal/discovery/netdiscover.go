package discovery

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// NetdiscoverPath reports the path to the netdiscover binary if it's on
// PATH, and whether it was found at all — mirrors NmapPath, since netdiscover
// is the same kind of "use it if it happens to be installed" enrichment nmap
// is, just for ARP-based discovery instead of port/service detail.
func NetdiscoverPath() (string, bool) {
	p, err := exec.LookPath("netdiscover")
	return p, err == nil
}

// NetdiscoverHost is one host line parsed out of netdiscover's output.
type NetdiscoverHost struct {
	IP     string
	MAC    string
	Vendor string
}

// RunNetdiscover runs an active ARP sweep of cidr on iface and returns every
// host that answered. Unlike nmap, there's no ARP equivalent of "-Pn against
// a pre-confirmed target list" worth using here: an ARP request/reply is
// negligible cost next to a TCP connect or ICMP echo, so sweeping the whole
// range directly (-f, netdiscover's fast mode) is simpler than reusing the
// built-in prober's alive list and just as cheap. What this adds on top of
// that prober: hosts that filter ICMP/TCP but still have to answer ARP to
// receive any IP traffic at all (aggressive host firewalls, minimal-stack
// IoT/OT gear), plus a MAC vendor lookup the built-in ARPTable() read never
// provides. It's Layer 2 only — iface/cidr must be a subnet this host is
// directly attached to, since ARP doesn't route; callers are responsible for
// only calling this for locally-attached subnets.
func RunNetdiscover(ctx context.Context, path, iface, cidr string, timeout time.Duration) ([]NetdiscoverHost, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// -P: parsable output (no colors/screen redraw). -N: skip the header
	// line. -f: fast mode, one ARP request per host instead of retrying,
	// which is what keeps a full-subnet sweep quick enough to run every scan
	// cycle. netdiscover exits on its own once the sweep finishes; the
	// context timeout is just a safety net in case it doesn't.
	cmd := exec.CommandContext(ctx, path, "-i", iface, "-r", cidr, "-P", "-N", "-f")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("netdiscover: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseNetdiscoverOutput(stdout.Bytes()), nil
}

// parseNetdiscoverOutput parses netdiscover's -P output: one host per line,
// whitespace-separated as "<ip> <mac> <count> <len> <vendor...>", where
// vendor is free text that can itself contain spaces (e.g. "Apple, Inc.").
func parseNetdiscoverOutput(out []byte) []NetdiscoverHost {
	var hosts []NetdiscoverHost
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		ip, mac := fields[0], fields[1]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		vendor := ""
		if len(fields) > 4 {
			vendor = strings.Join(fields[4:], " ")
		}
		hosts = append(hosts, NetdiscoverHost{IP: ip, MAC: mac, Vendor: vendor})
	}
	return hosts
}
