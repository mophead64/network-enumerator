package store

import (
	"database/sql"
	"time"

	"network-enumerator/internal/model"
)

func (s *Store) ListSubnets() ([]model.Subnet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, cidr, name, source, iface, discovered_at, last_scan_at, enabled, hidden FROM subnets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []model.Subnet{}
	for rows.Next() {
		var sn model.Subnet
		var lastScan sql.NullTime
		if err := rows.Scan(&sn.ID, &sn.CIDR, &sn.Name, &sn.Source, &sn.Iface, &sn.DiscoveredAt, &lastScan, &sn.Enabled, &sn.Hidden); err != nil {
			return nil, err
		}
		if lastScan.Valid {
			sn.LastScanAt = lastScan.Time
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// UpsertAutoSubnet registers a subnet discovered from a local interface.
// Returns the subnet id and whether it was newly created.
func (s *Store) UpsertAutoSubnet(cidr, name, iface string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var id int64
	err := s.db.QueryRow(`SELECT id FROM subnets WHERE cidr = ?`, cidr).Scan(&id)
	if err == nil {
		return id, false, nil
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}

	res, err := s.db.Exec(`INSERT INTO subnets (cidr, name, source, iface, discovered_at, enabled) VALUES (?, ?, 'auto', ?, ?, 1)`,
		cidr, name, iface, time.Now())
	if err != nil {
		return 0, false, err
	}
	id, err = res.LastInsertId()
	return id, true, err
}

func (s *Store) AddManualSubnet(cidr, name string) (model.Subnet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO subnets (cidr, name, source, iface, discovered_at, enabled) VALUES (?, ?, 'manual', '', ?, 1)`,
		cidr, name, now)
	if err != nil {
		return model.Subnet{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Subnet{}, err
	}
	return model.Subnet{ID: id, CIDR: cidr, Name: name, Source: "manual", DiscoveredAt: now, Enabled: true}, nil
}

func (s *Store) DeleteSubnet(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM subnets WHERE id = ?`, id)
	return err
}

func (s *Store) TouchSubnetScan(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE subnets SET last_scan_at = ? WHERE id = ?`, time.Now(), id)
	return err
}

// SetSubnetHidden suppresses (or restores) this subnet's hosts from the host
// list, graph, and dashboard counts. The subnet keeps scanning either way.
func (s *Store) SetSubnetHidden(id int64, hidden bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE subnets SET hidden = ? WHERE id = ?`, hidden, id)
	return err
}

// SetSubnetEnabled excludes (or re-includes) this subnet from scanning
// entirely — unlike Hidden, an excluded subnet's scan cycle is skipped
// outright (see Scanner.runOnce), so its existing hosts/ports are kept but
// stop being refreshed until it's re-included.
func (s *Store) SetSubnetEnabled(id int64, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE subnets SET enabled = ? WHERE id = ?`, enabled, id)
	return err
}
