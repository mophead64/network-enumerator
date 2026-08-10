package api

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"network-enumerator/internal/discovery"
	"network-enumerator/internal/model"
)

// importNmapXML restores hosts/ports from an nmap (or masscan) -oX scan run
// outside this app — see discovery.ParseNmapXML for the parsing, which
// treats both tools' output the same way. Unlike importNetworkMap/
// importDNSRecon, this is proof of actual liveness (the file only contains
// hosts the scan found up), so hosts land via UpsertHost with status "up"
// straight away rather than the "unknown, needs a scan cycle to confirm"
// status ImportHost/UpsertUnconfirmedHost use for merely-plausible sources
// like a stale export or a PTR record. Any address outside every known
// subnet gets its own auto-created /24, same fallback importDNSRecon uses.
func (s *Server) importNmapXML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	nmapHosts, err := discovery.ParseNmapXML(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid nmap XML: "+err.Error())
		return
	}
	if len(nmapHosts) == 0 {
		writeError(w, http.StatusBadRequest, "no up hosts found in that file")
		return
	}

	subnets, err := s.st.ListSubnets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	newSubnets, newHosts, newPorts, err := s.importNmapHosts(nmapHosts, subnets)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ev, _ := s.st.AddEvent("import", fmt.Sprintf(
		"Imported nmap scan: %d host(s) (%d new subnet(s), %d new host(s)), %d new open port(s)",
		len(nmapHosts), newSubnets, newHosts, newPorts), 0)
	s.hub.Broadcast(ev)
	s.scanner.TriggerNow()

	writeJSON(w, http.StatusOK, map[string]int{
		"hosts":      len(nmapHosts),
		"newSubnets": newSubnets,
		"newHosts":   newHosts,
		"newPorts":   newPorts,
	})
}

// importNmapHosts finds or creates the containing subnet for each host (see
// resolveSubnetFor) and upserts it and its open ports. subnets is mutated in
// place as new ones are created so a second host in the same newly-created
// /24 reuses it instead of creating a duplicate.
func (s *Server) importNmapHosts(nmapHosts []discovery.NmapHost, subnets []model.Subnet) (newSubnets, newHosts, newPorts int, err error) {
	for _, h := range nmapHosts {
		ip := net.ParseIP(h.IP)
		if ip == nil || ip.To4() == nil {
			continue
		}

		subnetID, created, err := s.resolveSubnetFor(&subnets, ip)
		if err != nil {
			return newSubnets, newHosts, newPorts, err
		}
		if created {
			newSubnets++
		}

		hostID, isNew, err := s.st.UpsertHost(subnetID, h.IP, h.MAC, h.Hostname, h.Vendor)
		if err != nil {
			return newSubnets, newHosts, newPorts, err
		}
		if isNew {
			newHosts++
		}

		n, err := s.importNmapPorts(hostID, h.Ports)
		if err != nil {
			return newSubnets, newHosts, newPorts, err
		}
		newPorts += n
	}
	return newSubnets, newHosts, newPorts, nil
}

// resolveSubnetFor returns the id of whichever subnet in *subnets contains
// ip (see subnetContaining), auto-creating a containing /24 (see
// containingSlash24, shared with importDNSRecon) and appending it to
// *subnets when none does.
func (s *Server) resolveSubnetFor(subnets *[]model.Subnet, ip net.IP) (subnetID int64, created bool, err error) {
	if id, ok := subnetContaining(*subnets, ip); ok {
		return id, false, nil
	}
	cidr := containingSlash24(ip)
	id, created, err := s.st.UpsertAutoSubnet(cidr, "", "")
	if err != nil {
		return 0, false, err
	}
	*subnets = append(*subnets, model.Subnet{ID: id, CIDR: cidr})
	return id, created, nil
}

// importNmapPorts upserts every open port nmap reported for one host and
// returns how many were newly created.
func (s *Server) importNmapPorts(hostID int64, ports []discovery.NmapPort) (newPorts int, err error) {
	for _, p := range ports {
		isNew, err := s.st.UpsertPort(hostID, p.Port, "tcp", p.Service, p.Banner, p.Product, p.Version)
		if err != nil {
			return newPorts, err
		}
		if isNew {
			newPorts++
		}
	}
	return newPorts, nil
}
