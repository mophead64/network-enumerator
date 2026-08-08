package api

import (
	"net"
	"net/http"

	"network-enumerator/internal/auth"
	"network-enumerator/internal/discovery"
	"network-enumerator/internal/store"
)

type Server struct {
	st       *store.Store
	scanner  *discovery.Scanner
	hub      *Hub
	sessions *auth.SessionStore
}

func New(st *store.Store, scanner *discovery.Scanner, hub *Hub) *Server {
	return &Server{st: st, scanner: scanner, hub: hub, sessions: auth.NewSessionStore()}
}

// Routes registers all API endpoints onto mux. The caller is responsible for
// also serving the static web UI on mux. Every endpoint requires an
// authenticated session except login and the health check.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	auth := s.requireAuth
	mux.HandleFunc("POST /api/auth/logout", auth(s.logout))
	mux.HandleFunc("GET /api/auth/me", auth(s.me))
	mux.HandleFunc("POST /api/auth/change-password", auth(s.changePassword))

	mux.HandleFunc("GET /api/subnets", auth(s.listSubnets))
	mux.HandleFunc("POST /api/subnets", auth(s.createSubnet))
	mux.HandleFunc("PATCH /api/subnets/{id}", auth(s.updateSubnet))
	mux.HandleFunc("DELETE /api/subnets/{id}", auth(s.deleteSubnet))

	mux.HandleFunc("GET /api/hosts", auth(s.listHosts))
	mux.HandleFunc("GET /api/hosts/{id}", auth(s.getHost))
	mux.HandleFunc("POST /api/hosts", auth(s.createHost))
	mux.HandleFunc("PATCH /api/hosts/{id}", auth(s.updateHost))
	mux.HandleFunc("DELETE /api/hosts/{id}", auth(s.deleteHost))
	mux.HandleFunc("DELETE /api/hosts", auth(s.clearAllHosts))
	mux.HandleFunc("POST /api/hosts/{id}/tags", auth(s.addHostTag))
	mux.HandleFunc("DELETE /api/hosts/{id}/tags/{tagId}", auth(s.removeHostTag))
	mux.HandleFunc("POST /api/hosts/{id}/ack", auth(s.acknowledgeHost))
	mux.HandleFunc("DELETE /api/hosts/{id}/ack", auth(s.unacknowledgeHost))
	mux.HandleFunc("POST /api/hosts/{id}/deep-scan", auth(s.deepScanHost))

	mux.HandleFunc("GET /api/tags", auth(s.listTags))
	mux.HandleFunc("POST /api/tags", auth(s.createTag))
	mux.HandleFunc("DELETE /api/tags/{id}", auth(s.deleteTag))

	mux.HandleFunc("GET /api/settings", auth(s.getSettings))
	mux.HandleFunc("PATCH /api/settings", auth(s.updateSettings))

	mux.HandleFunc("GET /api/risk-rules", auth(s.listRiskRules))
	mux.HandleFunc("POST /api/risk-rules", auth(s.createRiskRule))
	mux.HandleFunc("PATCH /api/risk-rules/{id}", auth(s.updateRiskRule))
	mux.HandleFunc("DELETE /api/risk-rules/{id}", auth(s.deleteRiskRule))

	mux.HandleFunc("GET /api/export/network-map", auth(s.exportNetworkMap))

	mux.HandleFunc("GET /api/events", auth(s.listEvents))
	mux.HandleFunc("GET /api/events/stream", auth(s.hub.ServeHTTP))

	mux.HandleFunc("POST /api/scan", auth(s.triggerScan))
	mux.HandleFunc("POST /api/scan/deep", auth(s.triggerDeepScan))
	mux.HandleFunc("GET /api/scan/status", auth(s.scanStatus))
}

// ---- subnets ----

func (s *Server) listSubnets(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.st.ListSubnets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, subnets)
}

func (s *Server) createSubnet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, "invalid CIDR: "+err.Error())
		return
	}
	sn, err := s.st.AddManualSubnet(req.CIDR, req.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.scanner.TriggerNow()
	writeJSON(w, http.StatusCreated, sn)
}

func (s *Server) updateSubnet(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Hidden  *bool `json:"hidden"`
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Hidden != nil {
		if err := s.st.SetSubnetHidden(id, *req.Hidden); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Enabled != nil {
		if err := s.st.SetSubnetEnabled(id, *req.Enabled); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteSubnet(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteSubnet(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- hosts ----

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.st.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.st.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubnetID int64  `json:"subnetId"`
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Notes    string `json:"notes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	if req.SubnetID == 0 {
		writeError(w, http.StatusBadRequest, "subnetId is required")
		return
	}
	h, err := s.st.AddManualHost(req.SubnetID, req.IP, req.Hostname, req.Notes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ev, _ := s.st.AddEvent("new_host", "Host manually added: "+h.IP, h.ID)
	s.hub.Broadcast(ev)
	writeJSON(w, http.StatusCreated, h)
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Notes *string `json:"notes"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Notes != nil {
		if err := s.st.UpdateHostNotes(id, *req.Notes); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	h, err := s.st.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteHost(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clearAllHostsPasscode is the confirmation number the Settings UI makes the
// user type before this destructive action runs. It's a misclick guard, not
// a security boundary — the whole endpoint already sits behind session auth.
const clearAllHostsPasscode = "1001"

func (s *Server) clearAllHosts(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("confirm") != clearAllHostsPasscode {
		writeError(w, http.StatusBadRequest, "missing or incorrect confirmation code")
		return
	}
	if err := s.st.ClearAllHosts(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ev, _ := s.st.AddEvent("hosts_cleared", "All hosts were cleared from inventory.", 0)
	s.hub.Broadcast(ev)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addHostTag(w http.ResponseWriter, r *http.Request) {
	hostID, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		TagID int64 `json:"tagId"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.st.AddHostTag(hostID, req.TagID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h, err := s.st.GetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) removeHostTag(w http.ResponseWriter, r *http.Request) {
	hostID, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid host id")
		return
	}
	tagID, err := pathID(r, "tagId")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	if err := s.st.RemoveHostTag(hostID, tagID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acknowledgeHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.AcknowledgeHost(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h, err := s.st.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) unacknowledgeHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.UnacknowledgeHost(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h, err := s.st.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) deepScanHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	h, err := s.st.GetHost(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if !s.scanner.TriggerDeepScan(h.ID, h.IP) {
		writeError(w, http.StatusConflict, "a deep scan is already running for this host")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// ---- tags ----

func (s *Server) listTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.st.ListTags()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tags)
}

func (s *Server) createTag(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	t, err := s.st.CreateTag(req.Name, req.Color)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) deleteTag(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.st.DeleteTag(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- events / scan control ----

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.st.ListEvents(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) triggerScan(w http.ResponseWriter, r *http.Request) {
	s.scanner.TriggerNow()
	writeJSON(w, http.StatusAccepted, s.scanner.Status())
}

func (s *Server) triggerDeepScan(w http.ResponseWriter, r *http.Request) {
	s.scanner.TriggerDeepScanAll()
	writeJSON(w, http.StatusAccepted, s.scanner.Status())
}

func (s *Server) scanStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.scanner.Status())
}
