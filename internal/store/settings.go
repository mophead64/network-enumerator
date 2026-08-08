package store

import "database/sql"

// Scan method preferences for the "scan_method" setting. Auto uses nmap when
// it's available on the host, falling back to the built-in TCP/ICMP prober
// otherwise; the other two force one or the other.
const (
	ScanMethodAuto = "auto"
	ScanMethodNmap = "nmap"
	ScanMethodTCP  = "tcp"
)

// GetScanMethod returns the configured scan method preference, defaulting to
// ScanMethodAuto when nothing has been set yet.
func (s *Store) GetScanMethod() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'scan_method'`).Scan(&v)
	if err == sql.ErrNoRows {
		return ScanMethodAuto, nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s *Store) SetScanMethod(method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES ('scan_method', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, method)
	return err
}

// GetNetdiscoverEnabled reports whether ARP-based discovery via netdiscover
// should be used when the binary is available, defaulting to true (the same
// "use it automatically if it's there" default nmap gets under
// ScanMethodAuto) when nothing has been set yet.
func (s *Store) GetNetdiscoverEnabled() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'netdiscover_enabled'`).Scan(&v)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return v == "true", nil
}

func (s *Store) SetNetdiscoverEnabled(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := "false"
	if enabled {
		v = "true"
	}
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES ('netdiscover_enabled', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, v)
	return err
}
