package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// MtrPath reports the path to the mtr binary if it's on PATH, and whether
// it was found at all — mirrors NmapPath/NetdiscoverPath/TraceroutePath.
func MtrPath() (string, bool) {
	p, err := exec.LookPath("mtr")
	return p, err == nil
}

// RunMTR runs mtr's JSON report mode against targetIP for cycles probes per
// hop and returns per-hop loss/RTT stats — the "deeper stats for one
// specific hop/path" step a user takes after a routine RunTraceroute scan
// already found the path, not something run automatically for every
// subnet (mtr's repeated probing per hop is much slower than a single
// traceroute pass). -n skips reverse DNS, same reasoning as RunTraceroute.
func RunMTR(ctx context.Context, path, targetIP string, cycles int, timeout time.Duration) ([]Hop, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-j", "-n", "-c", fmt.Sprintf("%d", cycles), targetIP)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mtr: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseMTRReport(stdout.Bytes())
}

// mtrReport mirrors the shape of `mtr -j`'s JSON output — see man mtr(8),
// "JSON OUTPUT". Loss%/Avg are mtr's own field names.
type mtrReport struct {
	Report struct {
		Hubs []struct {
			Count int     `json:"count"`
			Host  string  `json:"host"`
			LossP float64 `json:"Loss%"`
			Avg   float64 `json:"Avg"`
		} `json:"hubs"`
	} `json:"report"`
}

// parseMTRReport converts mtr -j's JSON report into the same Hop shape
// RunTraceroute produces. A hub whose host is "???" is mtr's own marker for
// a hop that never replied to any probe.
func parseMTRReport(data []byte) ([]Hop, error) {
	var report mtrReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse mtr output: %w", err)
	}

	hops := make([]Hop, 0, len(report.Report.Hubs))
	for _, h := range report.Report.Hubs {
		responded := h.Host != "" && h.Host != "???"
		hop := Hop{Index: h.Count, Responded: responded, LossPct: h.LossP}
		if responded {
			hop.IP = h.Host
			hop.RTTMs = h.Avg
		}
		hops = append(hops, hop)
	}
	return hops, nil
}
