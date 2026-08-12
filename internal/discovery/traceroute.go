package discovery

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// TraceroutePath reports the path to the traceroute binary if it's on PATH,
// and whether it was found at all — mirrors NmapPath/NetdiscoverPath.
func TraceroutePath() (string, bool) {
	p, err := exec.LookPath("traceroute")
	return p, err == nil
}

// Hop is one hop of a traced path to a target, shared by RunTraceroute and
// RunMTR — a target subnet's routine topology scan always uses traceroute
// (fast, no statistical signal needed for "what's the path"); mtr is only
// run on demand against one specific hop the user wants deeper loss/jitter
// stats for (see RunMTR).
type Hop struct {
	Index     int     `json:"index"` // 1-based hop number, as reported by the tool
	IP        string  `json:"ip,omitempty"`
	Responded bool    `json:"responded"` // false for a hop that timed out ("* * *")
	RTTMs     float64 `json:"rttMs,omitempty"`
	LossPct   float64 `json:"lossPct,omitempty"` // only ever populated by RunMTR — traceroute has no repeated-probe loss signal at -q1
}

// RunTraceroute runs a single-probe-per-hop traceroute to targetIP and
// returns every hop up to maxHops (or until the target itself replies,
// whichever the tool stops at first). -n skips reverse DNS (this app
// already knows what it's looking at, and DNS lookups just slow the trace
// down); -q1 is one probe per hop rather than the default three — this is
// meant to be a cheap "what's the path" check run routinely per subnet, not
// a statistical sample (that's what RunMTR is for); -w bounds how long a
// single unanswered probe can hold up the whole trace.
func RunTraceroute(ctx context.Context, path, targetIP string, maxHops int, perHopTimeout time.Duration) ([]Hop, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(maxHops)*perHopTimeout+5*time.Second)
	defer cancel()

	waitSecs := int(perHopTimeout.Seconds())
	if waitSecs < 1 {
		waitSecs = 1
	}
	cmd := exec.CommandContext(ctx, path, "-n", "-q", "1", "-w", strconv.Itoa(waitSecs), "-m", strconv.Itoa(maxHops), targetIP)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// traceroute exits non-zero when the destination never replies (e.g. the
	// last hop times out) even though every earlier hop's output is still
	// valid and useful — only treat it as a hard failure when there's no
	// output at all to parse.
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("traceroute: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseTracerouteOutput(stdout.Bytes()), nil
}

// parseTracerouteOutput parses traceroute's default text output, one hop
// per line: "<n>  <ip>  <rtt> ms" for a hop that replied, or "<n>  * " (or
// any line with no parseable IP in the second field) for one that didn't.
// The first line ("traceroute to ...") is skipped since it doesn't start
// with a hop number.
func parseTracerouteOutput(out []byte) []Hop {
	var hops []Hop
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			continue // not a hop line (banner, blank line, ...)
		}
		if fields[1] == "*" {
			hops = append(hops, Hop{Index: idx, Responded: false})
			continue
		}
		hop := Hop{Index: idx, IP: fields[1], Responded: true}
		for _, f := range fields[2:] {
			if ms, err := strconv.ParseFloat(f, 64); err == nil {
				hop.RTTMs = ms
				break
			}
		}
		hops = append(hops, hop)
	}
	return hops
}
