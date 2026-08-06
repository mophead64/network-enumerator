package api

import (
	"net/http"

	"network-enumerator/internal/model"
)

func (s *Server) listRiskRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.st.ListRiskRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) createRiskRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port         int    `json:"port"`
		Service      string `json:"service"`
		Severity     string `json:"severity"`
		Label        string `json:"label"`
		Enabled      bool   `json:"enabled"`
		VersionBelow string `json:"versionBelow"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}
	switch req.Severity {
	case "critical", "warning", "info":
	default:
		writeError(w, http.StatusBadRequest, "severity must be one of critical, warning, info")
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	rule, err := s.st.CreateRiskRule(model.RiskRule{
		Port: req.Port, Service: req.Service, Severity: req.Severity, Label: req.Label, Enabled: true,
		VersionBelow: req.VersionBelow,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) updateRiskRule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Port         *int    `json:"port"`
		Label        *string `json:"label"`
		Severity     *string `json:"severity"`
		Service      *string `json:"service"`
		VersionBelow *string `json:"versionBelow"`
		Enabled      *bool   `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Port != nil && (*req.Port <= 0 || *req.Port > 65535) {
		writeError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}
	if req.Label != nil && *req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	if req.Severity != nil {
		switch *req.Severity {
		case "critical", "warning", "info":
		default:
			writeError(w, http.StatusBadRequest, "severity must be one of critical, warning, info")
			return
		}
	}
	if err := s.st.UpdateRiskRule(id, req.Port, req.Label, req.Severity, req.Service, req.VersionBelow, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteRiskRule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteRiskRule(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
