package api

import (
	"net/http"

	"network-enumerator/internal/discovery"
	"network-enumerator/internal/model"
)

// toolStatus reports whether nmap/netdiscover/dnsrecon are installed on
// this host, and where — the topbar's combined tools icon, so their
// availability (and the exact binary a hover would want to confirm) is
// visible up front instead of only surfacing as a 409 from a mass/deep/
// reverse-DNS scan trigger later. Computed fresh on every request — each
// check is just an exec.LookPath, and PATH doesn't change over the life of
// this process, so there's nothing worth caching.
func (s *Server) toolStatus(w http.ResponseWriter, r *http.Request) {
	checks := []struct {
		name   string
		pathFn func() (string, bool)
	}{
		{"nmap", discovery.NmapPath},
		{"netdiscover", discovery.NetdiscoverPath},
		{"dnsrecon", discovery.DnsreconPath},
	}
	tools := make([]model.ToolStatus, 0, len(checks))
	for _, c := range checks {
		path, ok := c.pathFn()
		tools = append(tools, model.ToolStatus{Name: c.name, Available: ok, Path: path})
	}
	writeJSON(w, http.StatusOK, tools)
}
