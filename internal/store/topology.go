package store

import (
	"time"

	"network-enumerator/internal/model"
)

// ReplaceSubnetTopologyHops replaces every stored hop for a traced-to
// subnet with a fresh set from a new scan — a full replace rather than an
// upsert-by-index, since a hop count or path can shrink or grow between
// scans (a route change, a hop that starts/stops replying) and stale
// leftover rows from a longer previous path would otherwise linger forever.
func (s *Store) ReplaceSubnetTopologyHops(subnetID int64, hops []model.TopologyHop) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM topology_hops WHERE subnet_id = ?`, subnetID); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO topology_hops (subnet_id, hop_index, ip, responded, rtt_ms, loss_pct, method, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now()
	for _, h := range hops {
		if _, err := stmt.Exec(subnetID, h.HopIndex, h.IP, h.Responded, h.RTTMs, h.LossPct, h.Method, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListTopologyHops returns every stored hop across every subnet's most
// recent trace, ordered by subnet then hop index — the raw material
// discovery.BuildTopologyGraph classifies into a subnet-to-subnet link
// graph.
func (s *Store) ListTopologyHops() ([]model.TopologyHop, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id, subnet_id, hop_index, ip, responded, rtt_ms, loss_pct, method, scanned_at FROM topology_hops ORDER BY subnet_id, hop_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []model.TopologyHop{}
	for rows.Next() {
		var h model.TopologyHop
		if err := rows.Scan(&h.ID, &h.SubnetID, &h.HopIndex, &h.IP, &h.Responded, &h.RTTMs, &h.LossPct, &h.Method, &h.ScannedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
