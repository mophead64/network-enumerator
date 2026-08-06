package discovery

import (
	"bufio"
	"os"
	"strings"
)

// ARPTable returns a best-effort map of IP -> MAC address, read from the
// kernel's neighbor cache on Linux (/proc/net/arp). This only reflects
// hosts the kernel has already exchanged ARP with (typically ones we just
// probed on a locally-attached subnet), so it's called after host discovery
// rather than as a discovery mechanism on its own. On platforms without
// /proc/net/arp (e.g. macOS, when run locally rather than in the Linux
// container) it simply returns an empty map.
func ARPTable() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false // header line
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip, mac := fields[0], fields[3]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		out[ip] = mac
	}
	return out
}
