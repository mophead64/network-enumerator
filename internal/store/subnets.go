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

// UpsertAutoSubnet registers a subnet discovered from a local interface, or
// found in an imported network map (see importSegments). Returns the
// subnet id and whether it was newly created.
//
// On an existing match (by CIDR), name is filled in only if the subnet
// doesn't already have one — the same "only ever fills in what's missing"
// rule ImportHost applies to hosts. That matters because every caller
// shares this one upsert: the scanner and dnsrecon import always pass an
// empty name (they have none to give), so without this check they'd never
// touch it; but a network-map import does carry a name, and without the
// "only if blank" guard, re-importing an old export would clobber a name
// set since then via the rename-subnet UI or a newer import.
func (s *Store) UpsertAutoSubnet(cidr, name, iface string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var id int64
	var existingName string
	err := s.db.QueryRow(`SELECT id, name FROM subnets WHERE cidr = ?`, cidr).Scan(&id, &existingName)
	if err == nil {
		if name != "" && existingName == "" {
			if _, err := s.db.Exec(`UPDATE subnets SET name = ? WHERE id = ?`, name, id); err != nil {
				return 0, false, err
			}
		}
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

// SetSubnetName renames this subnet. The CIDR itself is intentionally not
// editable anywhere — it's the identity UpsertAutoSubnet matches on to avoid
// re-discovering the same subnet as a duplicate, and hosts reference the
// subnet by id, not by address range, so nothing depends on being able to
// change it after creation.
func (s *Store) SetSubnetName(id int64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE subnets SET name = ? WHERE id = ?`, name, id)
	return err
}
