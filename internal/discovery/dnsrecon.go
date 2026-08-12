package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DnsreconPath reports the path to the dnsrecon binary if it's on PATH, and
// whether it was found at all — mirrors NmapPath/NetdiscoverPath/DigPath.
// dnsrecon's -r mode reverse-resolves an entire CIDR/range in one process,
// which the scanner prefers over spawning `dig -x` once per candidate
// address when both happen to be installed (see Scanner.reverseDNSSweep).
func DnsreconPath() (string, bool) {
	p, err := exec.LookPath("dnsrecon")
	return p, err == nil
}

// ParseDNSReconJSON parses dnsrecon's -j output: a JSON array whose first
// element is a ScanInfo header object ({"arguments","date","type"}) followed
// by per-record entries. Real -r scans have been observed nesting each
// record in its own single-item array rather than listing them flat, so
// this walks the structure generically instead of assuming a fixed shape —
// any array is flattened, any object is inspected for record fields.
//
// Only "PTR" and "A" entries carry both an address and a name that map an
// IP to a hostname; every other record type dnsrecon can emit (NS, MX, SOA,
// TXT, SRV, the ScanInfo header itself, ...) is silently skipped rather than
// misread. Returns every IPv4 address that had one, mapped to the
// hostname(s) found for it in file order — one address can have more than
// one PTR record, which is why the value is a slice, not a single string.
func ParseDNSReconJSON(data []byte) (map[string][]string, error) {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode dnsrecon JSON: %w", err)
	}

	out := make(map[string][]string)
	seen := make(map[string]map[string]bool) // address -> names already recorded for it, for dedup
	collectDNSReconEntries(raw, out, seen)
	return out, nil
}

func collectDNSReconEntries(node any, out map[string][]string, seen map[string]map[string]bool) {
	switch v := node.(type) {
	case []any:
		for _, item := range v {
			collectDNSReconEntries(item, out, seen)
		}
	case map[string]any:
		typ, _ := v["type"].(string)
		if typ != "PTR" && typ != "A" {
			return
		}
		address, _ := v["address"].(string)
		name, _ := v["name"].(string)
		if address == "" || name == "" || net.ParseIP(address) == nil {
			return
		}
		if seen[address] == nil {
			seen[address] = make(map[string]bool)
		}
		if seen[address][name] {
			return
		}
		seen[address][name] = true
		out[address] = append(out[address], name)
	}
}

// RunDnsrecon runs `dnsrecon -r cidr -j <tmpfile>` — a reverse-DNS sweep of
// every address in cidr in a single process, instead of the fallback of
// spawning `dig -x` once per candidate address (see
// Scanner.reverseDNSSweep). dnsrecon's -j only writes to a file — there's no
// stdout/"-" option — so this uses a throwaway temp file and always cleans
// it up.
func RunDnsrecon(ctx context.Context, path, cidr string, timeout time.Duration) (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tmp, err := os.CreateTemp("", "dnsrecon-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	cmd := exec.CommandContext(ctx, path, "-r", cidr, "-j", tmpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("dnsrecon: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read dnsrecon output: %w", err)
	}
	return ParseDNSReconJSON(data)
}
