package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"network-enumerator/internal/model"
)

// The export* types below mirror the external "host and service" network
// map schema (segments/hosts/ports, snake_case fields) that other tooling
// consumes — a deliberately different shape from this app's own internal
// model (see internal/model/types.go), which uses numeric IDs and camelCase
// for its own API. exportNetworkMap is the only place that translates
// between the two.
type exportSegment struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CIDR        string `json:"cidr"`
	VLAN        string `json:"vlan,omitempty"`
	Description string `json:"description,omitempty"`
}

type exportHost struct {
	ID                 string `json:"id"`
	SegmentID          string `json:"segment_id"`
	Hostname           string `json:"hostname,omitempty"`
	IP                 string `json:"ip"`
	MAC                string `json:"mac,omitempty"`
	ManagementIP       string `json:"management_ip,omitempty"`
	DeviceType         string `json:"device_type,omitempty"`
	Criticality        string `json:"criticality,omitempty"`
	Vendor             string `json:"vendor,omitempty"`
	Model              string `json:"model,omitempty"`
	OS                 string `json:"os,omitempty"`
	Role               string `json:"role,omitempty"`
	Owner              string `json:"owner,omitempty"`
	VerificationStatus string `json:"verification_status,omitempty"`
	Notes              string `json:"notes,omitempty"`
}

type exportPort struct {
	HostID   string `json:"host_id"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

type exportDocument struct {
	Segments []exportSegment `json:"segments"`
	Hosts    []exportHost    `json:"hosts"`
	Ports    []exportPort    `json:"ports"`
}

func segmentExportID(subnetID int64) string { return fmt.Sprintf("seg-%d", subnetID) }
func hostExportID(hostID int64) string      { return fmt.Sprintf("host-%d", hostID) }

// hostExportNotes appends this host's computed risk findings (see
// riskForPorts) to its user notes, so the recommendations the app surfaces
// in-app (the risk badge's reasons on the host detail view) survive into the
// exported network map even though the external schema has no dedicated
// findings field.
func hostExportNotes(h model.Host) string {
	if len(h.RiskReasons) == 0 {
		return h.Notes
	}
	findings := "Flagged: " + strings.Join(h.RiskReasons, "; ")
	if h.Notes == "" {
		return findings
	}
	return h.Notes + "\n\n" + findings
}

// exportNetworkMap produces a JSON document of the currently-discovered
// network in the segments/hosts/ports schema used by external tooling. Only
// fields this app's automated scanning (ARP/netdiscover/nmap) actually
// populates are included; fields that would require a user to hand-curate
// data in-app just for this export (device_type, criticality, model, os,
// role, owner, verification_status, segment vlan/description) are left
// empty rather than guessed or turned into a manual-entry feature.
func (s *Server) exportNetworkMap(w http.ResponseWriter, r *http.Request) {
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

	doc := exportDocument{
		Segments: make([]exportSegment, 0, len(subnets)),
		Hosts:    make([]exportHost, 0, len(hosts)),
		Ports:    []exportPort{},
	}

	for _, sn := range subnets {
		doc.Segments = append(doc.Segments, exportSegment{
			ID:   segmentExportID(sn.ID),
			Name: sn.Name,
			CIDR: sn.CIDR,
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

	filename := fmt.Sprintf("network-map-export-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	writeJSON(w, http.StatusOK, doc)
}

// importNetworkMap restores subnets/hosts/ports from a document previously
// produced by exportNetworkMap — the "I lost my database, but I have last
// week's export" recovery path for a fresh run (in-memory, or a -db-file
// that doesn't exist yet) that would otherwise start from a completely
// empty inventory and wait for scan cycles to rediscover everything from
// scratch. It's an upsert, not a wipe-and-replace: re-importing the same
// file, or importing into a database that already has scan data, only ever
// fills in what's missing (see UpsertAutoSubnet/ImportHost) — it never
// overwrites data a live scan already found.
//
// Only ports the export marked "open" are restored — ListPorts (and so
// exportNetworkMap) also keeps closed ports around for history, but
// UpsertPort has no "closed" case to give them, and there's little value in
// resurrecting historical closed-port rows on a fresh database.
func (s *Server) importNetworkMap(w http.ResponseWriter, r *http.Request) {
	var doc exportDocument
	if err := readJSON(r, &doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or malformed network map JSON: "+err.Error())
		return
	}

	segmentIDs, err := s.importSegments(doc.Segments)
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

	ev, _ := s.st.AddEvent("import", fmt.Sprintf(
		"Imported network map: %d segment(s), %d host(s) (%d new), %d open port(s) (%d new)",
		len(segmentIDs), len(hostIDs), newHosts, len(doc.Ports), newPorts), 0)
	s.hub.Broadcast(ev)
	s.scanner.TriggerNow()

	writeJSON(w, http.StatusOK, map[string]int{
		"segments": len(segmentIDs),
		"hosts":    len(hostIDs),
		"newHosts": newHosts,
		"newPorts": newPorts,
	})
}

// importSegments upserts each segment by CIDR (see UpsertAutoSubnet) and
// returns the export's segment id -> real subnet id mapping the rest of the
// import uses to resolve each host's segment_id reference.
func (s *Server) importSegments(segments []exportSegment) (map[string]int64, error) {
	segmentIDs := make(map[string]int64, len(segments))
	for _, seg := range segments {
		if _, _, err := net.ParseCIDR(seg.CIDR); err != nil {
			continue // skip malformed entries rather than failing the whole import
		}
		id, _, err := s.st.UpsertAutoSubnet(seg.CIDR, seg.Name, "")
		if err != nil {
			return nil, err
		}
		segmentIDs[seg.ID] = id
	}
	return segmentIDs, nil
}

// importHosts upserts each host whose segment_id resolved above (see
// ImportHost) and returns the export's host id -> real host id mapping
// importPorts uses to resolve each port's host_id reference, plus how many
// were newly created.
func (s *Server) importHosts(hosts []exportHost, segmentIDs map[string]int64) (map[string]int64, int, error) {
	hostIDs := make(map[string]int64, len(hosts))
	var newHosts int
	for _, h := range hosts {
		subnetID, ok := segmentIDs[h.SegmentID]
		if !ok || net.ParseIP(h.IP) == nil {
			continue
		}
		id, isNew, err := s.st.ImportHost(subnetID, h.IP, h.MAC, h.Hostname, h.Vendor, h.Notes)
		if err != nil {
			return nil, 0, err
		}
		hostIDs[h.ID] = id
		if isNew {
			newHosts++
		}
	}
	return hostIDs, newHosts, nil
}

// importPorts upserts each open port whose host_id resolved above (see
// UpsertPort) and returns how many were newly created. Ports the export
// marked closed are skipped — see importNetworkMap's doc comment.
func (s *Server) importPorts(ports []exportPort, hostIDs map[string]int64) (int, error) {
	var newPorts int
	for _, p := range ports {
		hostID, ok := hostIDs[p.HostID]
		if !ok || p.Port <= 0 || p.State != "open" {
			continue
		}
		protocol := p.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		isNew, err := s.st.UpsertPort(hostID, p.Port, protocol, p.Service, p.Notes, "", p.Version)
		if err != nil {
			return 0, err
		}
		if isNew {
			newPorts++
		}
	}
	return newPorts, nil
}

func exportPortFrom(hostID int64, p model.Port) exportPort {
	version := p.Version
	if version == "" {
		version = p.Product
	}
	return exportPort{
		HostID:   hostExportID(hostID),
		Protocol: p.Protocol,
		Port:     p.Port,
		State:    p.State,
		Service:  p.Service,
		Version:  version,
		Notes:    p.Banner,
	}
}
