package api

import (
	"net/http"

	"network-enumerator/internal/discovery"
	"network-enumerator/internal/store"
)

type settingsResponse struct {
	ScanMethod    string `json:"scanMethod"`    // "auto" | "nmap" | "tcp" — the configured preference
	NmapAvailable bool   `json:"nmapAvailable"` // whether the nmap binary was found on PATH
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	method, err := s.st.GetScanMethod()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, available := discovery.NmapPath()
	writeJSON(w, http.StatusOK, settingsResponse{ScanMethod: method, NmapAvailable: available})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScanMethod string `json:"scanMethod"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.ScanMethod {
	case store.ScanMethodAuto, store.ScanMethodNmap, store.ScanMethodTCP:
	default:
		writeError(w, http.StatusBadRequest, "scanMethod must be one of: auto, nmap, tcp")
		return
	}
	if err := s.st.SetScanMethod(req.ScanMethod); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.getSettings(w, r)
}
