package api

import (
	"net/http"

	"network-enumerator/internal/discovery"
	"network-enumerator/internal/store"
	"network-enumerator/internal/version"
)

type settingsResponse struct {
	ScanMethod           string `json:"scanMethod"`           // "auto" | "nmap" | "tcp" — the configured preference
	NmapAvailable        bool   `json:"nmapAvailable"`        // whether the nmap binary was found on PATH
	NetdiscoverEnabled   bool   `json:"netdiscoverEnabled"`   // whether ARP discovery via netdiscover is used when available
	NetdiscoverAvailable bool   `json:"netdiscoverAvailable"` // whether the netdiscover binary was found on PATH
	Version              string `json:"version"`              // build version (see internal/version)
	BuildDate            string `json:"buildDate"`            // build timestamp, RFC3339 UTC (see internal/version)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	method, err := s.st.GetScanMethod()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	netdiscoverEnabled, err := s.st.GetNetdiscoverEnabled()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, nmapAvailable := discovery.NmapPath()
	_, netdiscoverAvailable := discovery.NetdiscoverPath()
	writeJSON(w, http.StatusOK, settingsResponse{
		ScanMethod:           method,
		NmapAvailable:        nmapAvailable,
		NetdiscoverEnabled:   netdiscoverEnabled,
		NetdiscoverAvailable: netdiscoverAvailable,
		Version:              version.Version,
		BuildDate:            version.BuildDate,
	})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScanMethod         *string `json:"scanMethod"`
		NetdiscoverEnabled *bool   `json:"netdiscoverEnabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ScanMethod != nil {
		switch *req.ScanMethod {
		case store.ScanMethodAuto, store.ScanMethodNmap, store.ScanMethodTCP:
		default:
			writeError(w, http.StatusBadRequest, "scanMethod must be one of: auto, nmap, tcp")
			return
		}
		if err := s.st.SetScanMethod(*req.ScanMethod); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.NetdiscoverEnabled != nil {
		if err := s.st.SetNetdiscoverEnabled(*req.NetdiscoverEnabled); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.getSettings(w, r)
}
