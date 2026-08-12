package api

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"

	"network-enumerator/internal/discovery"
	"network-enumerator/internal/model"
)

// importDNSRecon restores hostnames from a dnsrecon -j scan (see
// import-dns-recon.json for the schema, and discovery.ParseDNSReconJSON for
// how it's read) — a separate, additional import path from
// importNetworkMap's own export/import schema, not a replacement for it.
// dnsrecon only ever supplies an address and a hostname, so unlike
// importNetworkMap this can't restore MAC/vendor/ports — what it's for is
// enrichment: fill in a hostname on a host that's missing one (see
// Store.ImportHost, reused here unchanged), and create whatever subnet/host
// rows don't exist yet so a PTR sweep run outside this app still lands in
// it. New hosts land with status "unknown" for the same reason
// UpsertUnconfirmedHost's do — a PTR record isn't proof of liveness — and a
// subsequent scan cycle is triggered to try to confirm them.
func (s *Server) importDNSRecon(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	hostnamesByIP, err := discovery.ParseDNSReconJSON(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dnsrecon JSON: "+err.Error())
		return
	}
	if len(hostnamesByIP) == 0 {
		writeError(w, http.StatusBadRequest, "no PTR/A records found in that file")
		return
	}

	subnets, err := s.st.ListSubnets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	processed, newSubnets, newHosts, err := s.importDNSReconAddresses(hostnamesByIP, subnets)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ev, _ := s.st.AddEvent("import", fmt.Sprintf(
		"Imported dnsrecon scan: %d address(es), %d new subnet(s), %d new host(s)",
		processed, newSubnets, newHosts), 0)
	s.hub.Broadcast(ev)
	s.scanner.TriggerNow()

	writeJSON(w, http.StatusOK, map[string]int{
		"addresses":  processed,
		"newSubnets": newSubnets,
		"newHosts":   newHosts,
	})
}

// importDNSReconAddresses walks hostnamesByIP in sorted order (map iteration
// is random, and a stable order makes retries/logs reproducible), finding or
// creating the containing subnet for each address and then upserting the
// host via ImportHost — which is what actually fills in a missing hostname
// on an existing host, or creates a new "unknown"-status one. subnets is
// mutated in place as new ones are created so a second address in the same
// newly-created /24 reuses it instead of creating a duplicate.
func (s *Server) importDNSReconAddresses(hostnamesByIP map[string][]string, subnets []model.Subnet) (processed, newSubnets, newHosts int, err error) {
	ips := make([]string, 0, len(hostnamesByIP))
	for ip := range hostnamesByIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	for _, ipStr := range ips {
		names := hostnamesByIP[ipStr]
		ip := net.ParseIP(ipStr)
		if len(names) == 0 || ip == nil || ip.To4() == nil {
			continue
		}
		processed++

		subnetID, ok := subnetContaining(subnets, ip)
		if !ok {
			cidr := containingSlash24(ip)
			id, created, uerr := s.st.UpsertAutoSubnet(cidr, "", "")
			if uerr != nil {
				return processed, newSubnets, newHosts, uerr
			}
			subnetID = id
			if created {
				newSubnets++
			}
			subnets = append(subnets, model.Subnet{ID: id, CIDR: cidr})
		}

		_, isNew, ierr := s.st.ImportHost(subnetID, ipStr, "", names[0], "", "")
		if ierr != nil {
			return processed, newSubnets, newHosts, ierr
		}
		if isNew {
			newHosts++
		}
	}
	return processed, newSubnets, newHosts, nil
}

// subnetContaining returns the id of whichever subnet in subnets contains
// ip, if any.
func subnetContaining(subnets []model.Subnet, ip net.IP) (int64, bool) {
	for _, sn := range subnets {
		_, ipNet, err := net.ParseCIDR(sn.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return sn.ID, true
		}
	}
	return 0, false
}

// containingSlash24 returns the /24 CIDR containing ip — the fallback
// subnet grouping for a dnsrecon-discovered address that doesn't fall
// inside any subnet already known to this app. dnsrecon's own scan range
// (e.g. a /16) is usually far coarser than how this app organizes subnets
// elsewhere (auto-discovered local subnets, or a CIDR a user added by
// hand), so a /24 per address — the same granularity those already use —
// keeps imported subnets consistent with the rest of the inventory instead
// of dumping every address into one huge scanned-range "subnet".
func containingSlash24(ip net.IP) string {
	ip4 := ip.To4()
	mask := net.CIDRMask(24, 32)
	return (&net.IPNet{IP: ip4.Mask(mask), Mask: mask}).String()
}
