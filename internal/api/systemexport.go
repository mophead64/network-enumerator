package api

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"network-enumerator/internal/model"
	"network-enumerator/internal/store"
)

// systemSegment is like exportSegment, but additionally carries hidden/
// enabled — a system export is a full-fidelity backup of this app's own
// state (meant to be restored back into this app), unlike exportNetworkMap's
// deliberately external-tool-shaped schema, so there's no reason to drop
// that state on the way out.
type systemSegment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	Hidden  bool   `json:"hidden"`
	Enabled bool   `json:"enabled"`
}

// systemSettings mirrors the subset of settingsResponse that's actually
// user-configured (see getSettings) — nmap/netdiscover availability and
// build info are properties of the machine running the app, not saved state,
// so they're left out of the backup.
type systemSettings struct {
	ScanMethod         string `json:"scanMethod"`
	NetdiscoverEnabled bool   `json:"netdiscoverEnabled"`
}

type systemDocument struct {
	Segments  []systemSegment  `json:"segments"`
	Hosts     []exportHost     `json:"hosts"`
	Ports     []exportPort     `json:"ports"`
	Settings  systemSettings   `json:"settings"`
	RiskRules []model.RiskRule `json:"riskRules"`
}

// exportSystem produces a full backup of this app's own state — subnets
// (including hidden/disabled), hosts, ports, settings, and Risky service
// triage rules — as JSON. Unlike exportNetworkMap, this is meant to be
// restored via importSystem into this same app (or another instance of it),
// not consumed by other tooling.
func (s *Server) exportSystem(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.st.ListSubnets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hosts, err := s.st.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scanMethod, err := s.st.GetScanMethod()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	netdiscoverEnabled, err := s.st.GetNetdiscoverEnabled()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	riskRules, err := s.st.ListRiskRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	doc := systemDocument{
		Segments:  make([]systemSegment, 0, len(subnets)),
		Hosts:     make([]exportHost, 0, len(hosts)),
		Ports:     []exportPort{},
		Settings:  systemSettings{ScanMethod: scanMethod, NetdiscoverEnabled: netdiscoverEnabled},
		RiskRules: riskRules,
	}

	for _, sn := range subnets {
		doc.Segments = append(doc.Segments, systemSegment{
			ID:      segmentExportID(sn.ID),
			Name:    sn.Name,
			CIDR:    sn.CIDR,
			Hidden:  sn.Hidden,
			Enabled: sn.Enabled,
		})
	}

	for _, h := range hosts {
		doc.Hosts = append(doc.Hosts, exportHost{
			ID:           hostExportID(h.ID),
			SegmentID:    segmentExportID(h.SubnetID),
			Hostname:     h.Hostname,
			IP:           h.IP,
			MAC:          h.MAC,
			ManagementIP: h.IP,
			Vendor:       h.Vendor,
			Notes:        hostExportNotes(h),
		})
		for _, p := range h.Ports {
			doc.Ports = append(doc.Ports, exportPortFrom(h.ID, p))
		}
	}

	filename := fmt.Sprintf("system-export-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	writeJSON(w, http.StatusOK, doc)
}

// importSystem restores a document previously produced by exportSystem. Like
// importNetworkMap, subnets/hosts/ports are upserted rather than
// wipe-and-replaced (see importSegments/importHosts/importPorts) — but
// unlike importNetworkMap, each segment's hidden/enabled state is applied
// outright rather than only filled in when missing, since a system export is
// a faithful snapshot of that state rather than an external-tool document
// that never carries it at all. Settings are applied outright too.
func (s *Server) importSystem(w http.ResponseWriter, r *http.Request) {
	var doc systemDocument
	if err := readJSON(r, &doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or malformed system export JSON: "+err.Error())
		return
	}

	segmentIDs, err := s.importSystemSegments(doc.Segments)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hostIDs, newHosts, err := s.importHosts(doc.Hosts, segmentIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	newPorts, err := s.importPorts(doc.Ports, hostIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch doc.Settings.ScanMethod {
	case store.ScanMethodAuto, store.ScanMethodNmap, store.ScanMethodTCP:
		if err := s.st.SetScanMethod(doc.Settings.ScanMethod); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.st.SetNetdiscoverEnabled(doc.Settings.NetdiscoverEnabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	newRiskRules, updatedRiskRules, err := s.importRiskRules(doc.RiskRules)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ev, _ := s.st.AddEvent("import", fmt.Sprintf(
		"Imported system export: %d segment(s), %d host(s) (%d new), %d open port(s) (%d new), %d risk rule(s) (%d new), settings restored",
		len(segmentIDs), len(hostIDs), newHosts, len(doc.Ports), newPorts, len(doc.RiskRules), newRiskRules), 0)
	s.hub.Broadcast(ev)
	s.scanner.TriggerNow()

	writeJSON(w, http.StatusOK, map[string]int{
		"segments":         len(segmentIDs),
		"hosts":            len(hostIDs),
		"newHosts":         newHosts,
		"newPorts":         newPorts,
		"riskRules":        len(doc.RiskRules),
		"newRiskRules":     newRiskRules,
		"updatedRiskRules": updatedRiskRules,
	})
}

// importRiskRules restores the Risky service triage rule set from a system
// export. Rules have no natural export-time id worth preserving across
// instances (unlike segments/hosts, which key off CIDR/IP), so identity here
// is port+service+versionBelow — the fields that decide *what* a rule
// matches. A rule already present under that identity has its
// label/severity/enabled applied outright (same faithful-snapshot semantics
// as importSystemSegments' hidden/enabled); anything new is created.
// Returns how many rules were newly created vs. how many existing ones were
// updated.
func (s *Server) importRiskRules(rules []model.RiskRule) (created, updated int, err error) {
	existing, err := s.st.ListRiskRules()
	if err != nil {
		return 0, 0, err
	}
	type ruleKey struct {
		port         int
		service      string
		versionBelow string
	}
	byKey := make(map[ruleKey]model.RiskRule, len(existing))
	for _, r := range existing {
		byKey[ruleKey{r.Port, r.Service, r.VersionBelow}] = r
	}

	for _, r := range rules {
		k := ruleKey{r.Port, r.Service, r.VersionBelow}
		if match, ok := byKey[k]; ok {
			label, severity, versionBelow := r.Label, r.Severity, r.VersionBelow
			enabled := r.Enabled
			if err := s.st.UpdateRiskRule(match.ID, nil, &label, &severity, nil, &versionBelow, &enabled); err != nil {
				return created, updated, err
			}
			updated++
			continue
		}
		if _, err := s.st.CreateRiskRule(model.RiskRule{
			Port: r.Port, Service: r.Service, Severity: r.Severity,
			Label: r.Label, Enabled: r.Enabled, VersionBelow: r.VersionBelow,
		}); err != nil {
			return created, updated, err
		}
		created++
	}
	return created, updated, nil
}

// importSystemSegments is importSegments plus applying each segment's
// hidden/enabled state — see importSystem's doc comment for why this, unlike
// importSegments' name handling, always applies rather than only filling in
// what's missing.
func (s *Server) importSystemSegments(segments []systemSegment) (map[string]int64, error) {
	segmentIDs := make(map[string]int64, len(segments))
	for _, seg := range segments {
		if _, _, err := net.ParseCIDR(seg.CIDR); err != nil {
			continue // skip malformed entries rather than failing the whole import
		}
		id, _, err := s.st.UpsertAutoSubnet(seg.CIDR, seg.Name, "")
		if err != nil {
			return nil, err
		}
		if err := s.st.SetSubnetHidden(id, seg.Hidden); err != nil {
			return nil, err
		}
		if err := s.st.SetSubnetEnabled(id, seg.Enabled); err != nil {
			return nil, err
		}
		segmentIDs[seg.ID] = id
	}
	return segmentIDs, nil
}
