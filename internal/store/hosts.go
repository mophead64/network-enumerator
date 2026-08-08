package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"network-enumerator/internal/model"
)

// suspectMACThreshold is how many hosts on the same subnet sharing one MAC
// address it takes to flag them as suspect. A handful of legitimate devices
// can occasionally share a MAC (e.g. a VPN or bridge interface), but this
// many is the signature of a single device answering ARP for a whole range
// of addresses that aren't real distinct hosts.
const suspectMACThreshold = 8

// UpsertHost records a host seen during a scan. Returns the host id and
// whether this is the first time the host has ever been seen.
func (s *Store) UpsertHost(subnetID int64, ip, mac, hostname string) (id int64, isNew bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	err = s.db.QueryRow(`SELECT id FROM hosts WHERE subnet_id = ? AND ip = ?`, subnetID, ip).Scan(&id)
	if err == nil {
		args := []any{now}
		set := "last_seen = ?, status = 'up', miss_count = 0"
		if mac != "" {
			set += ", mac = ?"
			args = append(args, mac)
		}
		if hostname != "" {
			set += ", hostname = ?"
			args = append(args, hostname)
		}
		args = append(args, id)
		_, err = s.db.Exec(`UPDATE hosts SET `+set+` WHERE id = ?`, args...)
		return id, false, err
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}

	res, err := s.db.Exec(`INSERT INTO hosts (subnet_id, ip, mac, hostname, status, source, first_seen, last_seen, miss_count)
		VALUES (?, ?, ?, ?, 'up', 'auto', ?, ?, 0)`, subnetID, ip, mac, hostname, now, now)
	if err != nil {
		return 0, false, err
	}
	id, err = res.LastInsertId()
	return id, true, err
}

func (s *Store) AddManualHost(subnetID int64, ip, hostname, notes string) (model.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO hosts (subnet_id, ip, hostname, status, source, notes, first_seen, last_seen, miss_count)
		VALUES (?, ?, ?, 'up', 'manual', ?, ?, ?, 0)`, subnetID, ip, hostname, notes, now, now)
	if err != nil {
		return model.Host{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Host{}, err
	}
	return model.Host{ID: id, SubnetID: subnetID, IP: ip, Hostname: hostname, Status: "up", Source: "manual", Notes: notes, FirstSeen: now, LastSeen: now}, nil
}

func (s *Store) UpdateHostNotes(id int64, notes string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET notes = ? WHERE id = ?`, notes, id)
	return err
}

// AcknowledgeHost exempts a host from priority triage views until its open
// ports change again.
func (s *Store) AcknowledgeHost(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET acknowledged = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) UnacknowledgeHost(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET acknowledged = 0 WHERE id = ?`, id)
	return err
}

// ClearAcknowledgementIfSet un-acknowledges a host and reports whether it
// actually was acknowledged beforehand. Called when a new port is discovered
// open on the host, since a previously-reviewed host with a materially
// different port surface needs to be re-triaged as priority.
func (s *Store) ClearAcknowledgementIfSet(id int64) (wasAcknowledged bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var acked bool
	if err := s.db.QueryRow(`SELECT acknowledged FROM hosts WHERE id = ?`, id).Scan(&acked); err != nil {
		return false, err
	}
	if !acked {
		return false, nil
	}
	_, err = s.db.Exec(`UPDATE hosts SET acknowledged = 0 WHERE id = ?`, id)
	return true, err
}

func (s *Store) DeleteHost(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	return err
}

// ClearAllHosts wipes every host (and, via cascade, their ports and tag
// links) while leaving subnets, tags, and events in place.
func (s *Store) ClearAllHosts() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM hosts`)
	return err
}

// SweepMissingHosts increments miss_count for hosts in subnetID not present
// in seenIPs this cycle, and flips status to "down" after the host has been
// missed threshold consecutive times. Returns ids that just flipped to down.
func (s *Store) SweepMissingHosts(subnetID int64, seenIPs map[string]bool, threshold int) ([]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, ip, status, miss_count FROM hosts WHERE subnet_id = ?`, subnetID)
	if err != nil {
		return nil, err
	}
	type row struct {
		id        int64
		ip        string
		status    string
		missCount int
	}
	var candidates []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ip, &r.status, &r.missCount); err != nil {
			rows.Close()
			return nil, err
		}
		if !seenIPs[r.ip] {
			candidates = append(candidates, r)
		}
	}
	rows.Close()

	var justWentDown []int64
	for _, r := range candidates {
		missCount := r.missCount + 1
		status := r.status
		if missCount >= threshold && status != "down" {
			status = "down"
			justWentDown = append(justWentDown, r.id)
		}
		if _, err := s.db.Exec(`UPDATE hosts SET miss_count = ?, status = ? WHERE id = ?`, missCount, status, r.id); err != nil {
			return nil, err
		}
	}
	return justWentDown, nil
}

func (s *Store) ListHosts() ([]model.Host, error) {
	s.mu.Lock()
	hostRows, err := s.db.Query(`SELECT id, subnet_id, ip, mac, hostname, vendor, status, source, notes, first_seen, last_seen, acknowledged FROM hosts ORDER BY subnet_id, ip`)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	hosts := []model.Host{}
	for hostRows.Next() {
		var h model.Host
		if err := hostRows.Scan(&h.ID, &h.SubnetID, &h.IP, &h.MAC, &h.Hostname, &h.Vendor, &h.Status, &h.Source, &h.Notes, &h.FirstSeen, &h.LastSeen, &h.Acknowledged); err != nil {
			hostRows.Close()
			s.mu.Unlock()
			return nil, err
		}
		h.IsNew = time.Since(h.FirstSeen) < newHighlightWindow
		hosts = append(hosts, h)
	}
	hostRows.Close()

	rules, err := s.listRiskRulesLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	macCounts := make(map[string]int, len(hosts)) // "<subnetId>|<mac>" -> count
	for _, h := range hosts {
		if h.MAC == "" {
			continue
		}
		macCounts[macGroupKey(h.SubnetID, h.MAC)]++
	}

	for i := range hosts {
		tags, err := s.tagsForHost(hosts[i].ID)
		if err != nil {
			return nil, err
		}
		hosts[i].Tags = tags
		ports, err := s.ListPorts(hosts[i].ID)
		if err != nil {
			return nil, err
		}
		hosts[i].Ports = ports
		applySuspectFlag(&hosts[i], macCounts[macGroupKey(hosts[i].SubnetID, hosts[i].MAC)])
		hosts[i].RiskLevel, hosts[i].RiskReasons = riskForPorts(ports, rules)
	}
	return hosts, nil
}

func (s *Store) GetHost(id int64) (model.Host, error) {
	s.mu.Lock()
	var h model.Host
	err := s.db.QueryRow(`SELECT id, subnet_id, ip, mac, hostname, vendor, status, source, notes, first_seen, last_seen, acknowledged FROM hosts WHERE id = ?`, id).
		Scan(&h.ID, &h.SubnetID, &h.IP, &h.MAC, &h.Hostname, &h.Vendor, &h.Status, &h.Source, &h.Notes, &h.FirstSeen, &h.LastSeen, &h.Acknowledged)
	if err != nil {
		s.mu.Unlock()
		return h, err
	}
	var macCount int
	if h.MAC != "" {
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE subnet_id = ? AND mac = ?`, h.SubnetID, h.MAC).Scan(&macCount); err != nil {
			s.mu.Unlock()
			return h, err
		}
	}
	rules, err := s.listRiskRulesLocked()
	s.mu.Unlock()
	if err != nil {
		return h, err
	}

	h.IsNew = time.Since(h.FirstSeen) < newHighlightWindow
	applySuspectFlag(&h, macCount)
	h.Tags, err = s.tagsForHost(h.ID)
	if err != nil {
		return h, err
	}
	h.Ports, err = s.ListPorts(h.ID)
	if err != nil {
		return h, err
	}
	h.RiskLevel, h.RiskReasons = riskForPorts(h.Ports, rules)
	return h, err
}

func macGroupKey(subnetID int64, mac string) string {
	return fmt.Sprintf("%d|%s", subnetID, mac)
}

func applySuspectFlag(h *model.Host, macCountOnSubnet int) {
	if h.MAC == "" || macCountOnSubnet < suspectMACThreshold {
		return
	}
	h.Suspect = true
	h.SuspectReason = fmt.Sprintf(
		"MAC %s is shared by %d hosts on this subnet — likely one device (e.g. a router doing proxy ARP) answering for addresses that aren't real distinct hosts, not %d separate devices.",
		h.MAC, macCountOnSubnet, macCountOnSubnet)
}

// riskForPorts matches a host's open ports against the configured risk
// rules and returns the highest severity found plus the human-readable
// reasons behind it.
func riskForPorts(ports []model.Port, rules []model.RiskRule) (level string, reasons []string) {
	severityRank := map[string]int{"info": 1, "warning": 2, "critical": 3}
	best := 0
	for _, p := range ports {
		if p.State != "open" {
			continue // a closed port isn't an active exposure, whatever it used to run
		}
		for _, r := range rules {
			if !r.Enabled || r.Port != p.Port {
				continue
			}
			if r.Service != "" {
				// nmap reports a generic service name ("http", "ssh") separately
				// from the specific product it detected ("Apache httpd",
				// "OpenSSH") — a rule targeting a specific product (needed to
				// tell Apache and nginx apart, since both just report "http")
				// has to check both, not just the generic name.
				svc := strings.ToLower(r.Service)
				if !strings.Contains(strings.ToLower(p.Service), svc) && !strings.Contains(strings.ToLower(p.Product), svc) {
					continue
				}
			}
			reason := fmt.Sprintf("%d/%s: %s", p.Port, p.Protocol, r.Label)
			if r.VersionBelow != "" {
				// A version-gated rule only fires against a port with actual
				// detected version data (nmap's -sV) — a port scanned by the
				// built-in prober, or one nmap couldn't identify, has nothing
				// to compare and never matches this kind of rule.
				if p.Version == "" || !versionLess(p.Version, r.VersionBelow) {
					continue
				}
				detected := strings.TrimSpace(p.Product + " " + p.Version)
				reason = fmt.Sprintf("%d/%s: %s (detected %s, flagged below version %s)", p.Port, p.Protocol, r.Label, detected, r.VersionBelow)
			}
			reasons = append(reasons, reason)
			if rank := severityRank[r.Severity]; rank > best {
				best = rank
				level = r.Severity
			}
		}
	}
	return level, reasons
}
