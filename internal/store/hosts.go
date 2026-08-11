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

// UpsertHost records a host seen during a scan. mac/hostname/vendor are only
// applied when non-empty, so a later call with less information (e.g. a
// plain TCP probe after netdiscover already supplied a vendor) never clobbers
// what's already known. Returns the host id and whether this is the first
// time the host has ever been seen.
func (s *Store) UpsertHost(subnetID int64, ip, mac, hostname, vendor string) (id int64, isNew bool, err error) {
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
		if vendor != "" {
			set += ", vendor = ?"
			args = append(args, vendor)
		}
		args = append(args, id)
		_, err = s.db.Exec(`UPDATE hosts SET `+set+` WHERE id = ?`, args...)
		return id, false, err
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}

	res, err := s.db.Exec(`INSERT INTO hosts (subnet_id, ip, mac, hostname, vendor, status, source, first_seen, last_seen, miss_count)
		VALUES (?, ?, ?, ?, ?, 'up', 'auto', ?, ?, 0)`, subnetID, ip, mac, hostname, vendor, now, now)
	if err != nil {
		return 0, false, err
	}
	id, err = res.LastInsertId()
	return id, true, err
}

// UpsertUnconfirmedHost records a host seen only via a passive signal — a
// dig -x PTR record with no ping/TCP/ARP response to back it up — rather
// than a live probe. Unlike UpsertHost, an existing row's status/miss_count/
// last_seen are never touched here: a PTR record is a static DNS entry that
// persists whether or not the device behind it is even powered on, so it
// must never be able to promote a host to "up" (or protect one from ever
// going "down") by itself. A brand-new row is inserted with status
// "unknown" — neither "up" nor "down" — until an open port actually
// confirms it via ConfirmHostUp. Returns the host id and whether this is the
// first time the host has ever been seen.
func (s *Store) UpsertUnconfirmedHost(subnetID int64, ip, hostname string) (id int64, isNew bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var existingHostname string
	err = s.db.QueryRow(`SELECT id, hostname FROM hosts WHERE subnet_id = ? AND ip = ?`, subnetID, ip).Scan(&id, &existingHostname)
	if err == nil {
		if hostname != "" && existingHostname == "" {
			_, err = s.db.Exec(`UPDATE hosts SET hostname = ? WHERE id = ?`, hostname, id)
		}
		return id, false, err
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}

	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO hosts (subnet_id, ip, hostname, status, source, first_seen, last_seen, miss_count)
		VALUES (?, ?, ?, 'unknown', 'auto', ?, ?, 0)`, subnetID, ip, hostname, now, now)
	if err != nil {
		return 0, false, err
	}
	id, err = res.LastInsertId()
	return id, true, err
}

// ConfirmHostUp promotes a host recorded via UpsertUnconfirmedHost to a
// genuinely confirmed "up" once a port scan finds an open port on it — the
// real liveness proof a PTR record alone can never provide.
func (s *Store) ConfirmHostUp(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET status = 'up', miss_count = 0, last_seen = ? WHERE id = ?`, time.Now(), id)
	return err
}

// ImportHost records a host from a previously-exported network map — the
// "I lost my database, but I have last week's export" recovery path.
// Like UpsertUnconfirmedHost, this is a historical record rather than a
// live probe result, so a brand-new row lands with status "unknown" rather
// than "up": the export is a snapshot of what was once true, and only the
// scan cycle that follows the import (or a later one) can actually confirm
// it. An existing row — already discovered by this session's own scanning,
// or a previous import — is left with whatever status/miss_count/last_seen
// it already has; only its empty mac/hostname/vendor fields are filled in,
// and notes are only ever set on first import so a re-import can't clobber
// notes added since. Returns the host id and whether this is the first
// time the host has ever been seen.
func (s *Store) ImportHost(subnetID int64, ip, mac, hostname, vendor, notes string) (id int64, isNew bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var existingMAC, existingHostname, existingVendor string
	err = s.db.QueryRow(`SELECT id, mac, hostname, vendor FROM hosts WHERE subnet_id = ? AND ip = ?`, subnetID, ip).
		Scan(&id, &existingMAC, &existingHostname, &existingVendor)
	if err == nil {
		var sets []string
		var args []any
		if mac != "" && existingMAC == "" {
			sets = append(sets, "mac = ?")
			args = append(args, mac)
		}
		if hostname != "" && existingHostname == "" {
			sets = append(sets, "hostname = ?")
			args = append(args, hostname)
		}
		if vendor != "" && existingVendor == "" {
			sets = append(sets, "vendor = ?")
			args = append(args, vendor)
		}
		if len(sets) == 0 {
			return id, false, nil
		}
		args = append(args, id)
		_, err = s.db.Exec(`UPDATE hosts SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
		return id, false, err
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}

	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO hosts (subnet_id, ip, mac, hostname, vendor, status, source, notes, first_seen, last_seen, miss_count)
		VALUES (?, ?, ?, ?, ?, 'unknown', 'auto', ?, ?, ?, 0)`, subnetID, ip, mac, hostname, vendor, notes, now, now)
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

// SetHostHostname manually sets a host's hostname (e.g. via the host
// modal) — a later scan/import may still overwrite it, the same as any
// auto-discovered value.
func (s *Store) SetHostHostname(id int64, hostname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET hostname = ? WHERE id = ?`, hostname, id)
	return err
}

// SetHostMAC manually sets a host's MAC address — mirrors SetHostHostname.
func (s *Store) SetHostMAC(id int64, mac string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET mac = ? WHERE id = ?`, mac, id)
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

// AcknowledgeHostNew dismisses this host's NEW badge for good. Unlike
// AcknowledgeHost (priority triage, auto-cleared the moment a new port
// opens), this is a one-time, one-way acknowledgement: nothing ever flips
// new_ack back to 0, and a host's "new" status no longer expires on its own
// after a fixed window — see IsNew in ListHosts/GetHost.
func (s *Store) AcknowledgeHostNew(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE hosts SET new_ack = 1 WHERE id = ?`, id)
	return err
}

// AcknowledgeAllHostsNew is the bulk version of AcknowledgeHostNew — dismisses
// the NEW badge for every host at once, offered from Settings for clearing a
// backlog in one action rather than host by host. Returns how many hosts
// were actually still new (and so got touched).
func (s *Store) AcknowledgeAllHostsNew() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE hosts SET new_ack = 1 WHERE new_ack = 0`)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
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
		// Only a confirmed "up" host can go "down" — "unknown" hosts (dig -x
		// PTR only, never an open port) were never actually confirmed alive,
		// so missing them again and again is expected, not a state change.
		if missCount >= threshold && status == "up" {
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
	hostRows, err := s.db.Query(`SELECT id, subnet_id, ip, mac, hostname, vendor, status, source, notes, first_seen, last_seen, acknowledged, new_ack FROM hosts ORDER BY subnet_id, ip`)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	hosts := []model.Host{}
	for hostRows.Next() {
		var h model.Host
		var newAck bool
		if err := hostRows.Scan(&h.ID, &h.SubnetID, &h.IP, &h.MAC, &h.Hostname, &h.Vendor, &h.Status, &h.Source, &h.Notes, &h.FirstSeen, &h.LastSeen, &h.Acknowledged, &newAck); err != nil {
			hostRows.Close()
			s.mu.Unlock()
			return nil, err
		}
		h.IsNew = !newAck
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
	var newAck bool
	err := s.db.QueryRow(`SELECT id, subnet_id, ip, mac, hostname, vendor, status, source, notes, first_seen, last_seen, acknowledged, new_ack FROM hosts WHERE id = ?`, id).
		Scan(&h.ID, &h.SubnetID, &h.IP, &h.MAC, &h.Hostname, &h.Vendor, &h.Status, &h.Source, &h.Notes, &h.FirstSeen, &h.LastSeen, &h.Acknowledged, &newAck)
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

	h.IsNew = !newAck
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
