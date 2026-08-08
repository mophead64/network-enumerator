package api

import (
	"fmt"
	"net/http"
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

// exportNetworkMap produces a JSON document of the currently-discovered
// network in the segments/hosts/ports schema used by external tooling.
// Fields this app doesn't track (device_type, criticality, model, os, role,
// owner, verification_status, segment vlan/description) are left empty
// rather than guessed.
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
			ManagementIP: h.IP,
			Vendor:       h.Vendor,
			Notes:        h.Notes,
		})
		for _, p := range h.Ports {
			doc.Ports = append(doc.Ports, exportPortFrom(h.ID, p))
		}
	}

	filename := fmt.Sprintf("network-map-export-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	writeJSON(w, http.StatusOK, doc)
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
