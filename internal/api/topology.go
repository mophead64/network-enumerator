package api

import (
	"net"
	"net/http"
	"time"

	"network-enumerator/internal/discovery"
)

// triggerTopologyScan mirrors triggerMassScan/triggerReverseDNSScan's
// availability gate: a "Topology scan" (traceroute to one host per subnet,
// see Scanner.scanSubnetTopology) is rejected up front with a clear 409 if
// traceroute isn't installed, rather than silently queuing a cycle that
// will find nothing.
func (s *Server) triggerTopologyScan(w http.ResponseWriter, r *http.Request) {
	if _, ok := discovery.TraceroutePath(); !ok {
		writeError(w, http.StatusConflict, "traceroute isn't installed on this host — topology scan requires it")
		return
	}
	s.scanner.TriggerTopologyScanAll()
	writeJSON(w, http.StatusAccepted, s.scanner.Status())
}

// topologyResponse is discovery.BuildTopologyGraph's graph plus the IPs
// this host itself answers on (see discovery.LocalIPs) — the Map view uses
// OriginIPs to find whichever already-discovered host is literally this
// machine and highlight it directly, rather than drawing a separate
// synthetic "this host" node for the trace origin.
type topologyResponse struct {
	discovery.TopologyGraph
	OriginIPs []string `json:"originIps"`
}

// getTopology returns the merged subnet-to-subnet link graph built from
// every subnet's most recently traced hops (see
// discovery.BuildTopologyGraph) — the data source for the Map view and the
// draw.io export's router links. Returns an empty graph (not an error) when
// no topology scan has run yet, so callers don't need special-case
// handling for "nothing scanned" versus "scan found nothing."
func (s *Server) getTopology(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.st.ListSubnets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hops, err := s.st.ListTopologyHops()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A failure here (no interfaces enumerable, sandboxed environment, ...)
	// just means the highlight won't show up — not worth failing the whole
	// request over.
	localIPs, _ := discovery.LocalIPs()
	writeJSON(w, http.StatusOK, topologyResponse{
		TopologyGraph: discovery.BuildTopologyGraph(subnets, hops),
		OriginIPs:     localIPs,
	})
}

// topologyMTRCycles/topologyMTRTimeout bound the on-demand "deeper stats
// for this one hop" request: a handful of probe cycles is enough for a
// meaningful loss/jitter reading without keeping the HTTP request open too
// long — this runs synchronously, unlike the deep-scan-host action, since
// it finishes in a few seconds rather than minutes.
const (
	topologyMTRCycles  = 5
	topologyMTRTimeout = 15 * time.Second
)

// runTopologyMTR is the "request an mtr report for a specific hop" action
// notes.txt describes: given one IP (typically a router discovered by the
// routine traceroute-based topology scan), runs mtr synchronously and
// returns its per-hop loss/RTT stats directly in the response. Not
// persisted — this is a one-off deeper look, not a replacement for the
// stored traceroute hop it's usually requested against.
func (s *Server) runTopologyMTR(w http.ResponseWriter, r *http.Request) {
	path, ok := discovery.MtrPath()
	if !ok {
		writeError(w, http.StatusConflict, "mtr isn't installed on this host — this action requires it")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	hops, err := discovery.RunMTR(r.Context(), path, req.IP, topologyMTRCycles, topologyMTRTimeout)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, hops)
}
