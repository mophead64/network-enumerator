package store

import (
	"database/sql"
	"time"

	"network-enumerator/internal/model"
)

const newHighlightWindow = 15 * time.Minute

// UpsertPort records an open port seen during a scan. banner/product/version
// come from whichever scan path found the port: the built-in TCP prober only
// ever supplies banner, nmap's enrichment pass only ever supplies
// product/version (see Scanner.scanSubnetNmap, which records a port via the
// TCP path first and enriches the same row with a second call once nmap's
// results land) — so an update only overwrites each of these when the new
// value is non-empty, the same way mac/hostname already work in UpsertHost.
// Otherwise the enrichment call's empty banner would blank out the banner
// the TCP call had just recorded moments earlier, and vice versa. Returns
// whether this is the first time this port has been seen open on this host.
func (s *Store) UpsertPort(hostID int64, port int, protocol, service, banner, product, version string) (isNew bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var id int64
	err = s.db.QueryRow(`SELECT id FROM ports WHERE host_id = ? AND port = ? AND protocol = ?`, hostID, port, protocol).Scan(&id)
	if err == nil {
		args := []any{now, service}
		set := "last_seen = ?, state = 'open', service = ?"
		if banner != "" {
			set += ", banner = ?"
			args = append(args, banner)
		}
		if product != "" {
			set += ", product = ?"
			args = append(args, product)
		}
		if version != "" {
			set += ", version = ?"
			args = append(args, version)
		}
		args = append(args, id)
		_, err = s.db.Exec(`UPDATE ports SET `+set+` WHERE id = ?`, args...)
		return false, err
	}
	if err != sql.ErrNoRows {
		return false, err
	}

	_, err = s.db.Exec(`INSERT INTO ports (host_id, port, protocol, state, service, banner, product, version, first_seen, last_seen)
		VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)`, hostID, port, protocol, service, banner, product, version, now, now)
	return true, err
}

// SweepClosedPorts marks ports as closed if they were actually probed this
// cycle (in probedPorts) but not found open (not in openPorts). probedPorts
// matters because a scan cycle might only check a curated subset of ports
// (CommonPorts) rather than the full range — a stored open port outside
// that subset was never re-checked and must not be swept as closed just for
// being absent from openPorts, or an on-demand deep scan's findings would
// get silently closed out by the very next ordinary scan cycle. Returns the
// port numbers that just transitioned to closed.
func (s *Store) SweepClosedPorts(hostID int64, probedPorts, openPorts map[int]bool) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, port, state FROM ports WHERE host_id = ?`, hostID)
	if err != nil {
		return nil, err
	}
	type row struct {
		id    int64
		port  int
		state string
	}
	var toClose []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.port, &r.state); err != nil {
			rows.Close()
			return nil, err
		}
		if probedPorts[r.port] && !openPorts[r.port] && r.state == "open" {
			toClose = append(toClose, r)
		}
	}
	rows.Close()

	var closed []int
	for _, r := range toClose {
		if _, err := s.db.Exec(`UPDATE ports SET state = 'closed' WHERE id = ?`, r.id); err != nil {
			return nil, err
		}
		closed = append(closed, r.port)
	}
	return closed, nil
}

// ListPorts returns every port ever recorded open on hostID, regardless of
// its current state — a port that's since closed stays on the host with
// State "closed" rather than disappearing, so its history (banner, product,
// version, first/last seen) isn't lost the moment it stops answering.
// Open ports sort first, then by port number.
func (s *Store) ListPorts(hostID int64) ([]model.Port, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, host_id, port, protocol, state, service, banner, product, version, first_seen, last_seen
		FROM ports WHERE host_id = ? ORDER BY (state != 'open'), port`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []model.Port{}
	for rows.Next() {
		var p model.Port
		if err := rows.Scan(&p.ID, &p.HostID, &p.Port, &p.Protocol, &p.State, &p.Service, &p.Banner, &p.Product, &p.Version, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		p.IsNew = time.Since(p.FirstSeen) < newHighlightWindow
		out = append(out, p)
	}
	return out, rows.Err()
}
