package store

import (
	"strings"

	"network-enumerator/internal/model"
)

// defaultRiskRules seed the out-of-the-box triage rules: legacy/unencrypted
// or high-value-target services worth hardening or investigating first, plus
// a handful of known-vulnerable version thresholds for widely-deployed
// services (below). Fully editable afterwards via the risk rules API/
// Settings UI.
var defaultRiskRules = []model.RiskRule{
	{Port: 23, Severity: "critical", Label: "Telnet — unencrypted remote access", Enabled: true},
	{Port: 21, Severity: "warning", Label: "FTP — unencrypted file transfer", Enabled: true},
	{Port: 5900, Severity: "critical", Label: "VNC — often unauthenticated remote desktop", Enabled: true},
	{Port: 5901, Severity: "critical", Label: "VNC — often unauthenticated remote desktop", Enabled: true},
	{Port: 512, Severity: "critical", Label: "rexec — legacy unencrypted remote exec", Enabled: true},
	{Port: 513, Severity: "critical", Label: "rlogin — legacy unencrypted remote login", Enabled: true},
	{Port: 514, Severity: "critical", Label: "rsh — legacy unencrypted remote shell", Enabled: true},
	{Port: 80, Severity: "warning", Label: "Plain HTTP — unencrypted web management", Enabled: true},
	{Port: 161, Severity: "warning", Label: "SNMP — check for default community strings", Enabled: true},
	{Port: 139, Severity: "warning", Label: "NetBIOS — legacy Windows file sharing", Enabled: true},
	{Port: 445, Severity: "warning", Label: "SMB — frequent lateral-movement/ransomware target", Enabled: true},
	{Port: 3389, Severity: "critical", Label: "RDP — high-value target, patch and restrict access", Enabled: true},
	{Port: 22, Severity: "info", Label: "SSH exposed — verify key-only auth and patch level", Enabled: true},

	// Known-vulnerable version thresholds for common services, only usable
	// against nmap's version detection (a port with no detected Version
	// never matches these — see riskForPorts). The version string a service
	// reports isn't proof either way (a distro can backport a fix onto an
	// old-looking version number, or a build can be a custom fork), so these
	// are a starting heuristic to prioritize what to verify first, not a
	// confirmed-vulnerable determination — the label says so and names the
	// CVE so it can be checked independently. Not exhaustive: add more via
	// Settings for services/ports specific to a given engagement.
	{Port: 22, Service: "openssh", Severity: "warning", VersionBelow: "7.4", Enabled: true,
		Label: "OpenSSH — versions before 7.4 have several known CVEs (e.g. username enumeration); verify patch level"},
	{Port: 21, Service: "proftpd", Severity: "critical", VersionBelow: "1.3.5", Enabled: true,
		Label: "ProFTPD — versions before 1.3.5 are vulnerable to CVE-2015-3306 (unauthenticated arbitrary file copy via mod_copy)"},
	{Port: 80, Service: "apache", Severity: "critical", VersionBelow: "2.4.51", Enabled: true,
		Label: "Apache httpd — versions before 2.4.51 are vulnerable to CVE-2021-41773 / CVE-2021-42013 (path traversal & RCE), actively exploited"},
	{Port: 443, Service: "apache", Severity: "critical", VersionBelow: "2.4.51", Enabled: true,
		Label: "Apache httpd — versions before 2.4.51 are vulnerable to CVE-2021-41773 / CVE-2021-42013 (path traversal & RCE), actively exploited"},
	{Port: 80, Service: "nginx", Severity: "warning", VersionBelow: "1.21.0", Enabled: true,
		Label: "nginx — versions before 1.21.0 (1.20.1 on the stable branch) are vulnerable to CVE-2021-23017 (DNS resolver off-by-one); relevant if the resolver directive is used"},
	{Port: 443, Service: "nginx", Severity: "warning", VersionBelow: "1.21.0", Enabled: true,
		Label: "nginx — versions before 1.21.0 (1.20.1 on the stable branch) are vulnerable to CVE-2021-23017 (DNS resolver off-by-one); relevant if the resolver directive is used"},
}

// ensureDefaultRiskRules seeds the built-in rule set on first run only; once
// any rule exists (including all deleted down to zero by the user) it's left
// alone.
func (s *Store) ensureDefaultRiskRules() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM risk_rules`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	for _, r := range defaultRiskRules {
		if _, err := s.db.Exec(`INSERT INTO risk_rules (port, service, severity, label, enabled, version_below) VALUES (?, ?, ?, ?, ?, ?)`,
			r.Port, r.Service, r.Severity, r.Label, r.Enabled, r.VersionBelow); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListRiskRules() ([]model.RiskRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listRiskRulesLocked()
}

// listRiskRulesLocked must be called with s.mu already held.
func (s *Store) listRiskRulesLocked() ([]model.RiskRule, error) {
	rows, err := s.db.Query(`SELECT id, port, service, severity, label, enabled, version_below FROM risk_rules ORDER BY port, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RiskRule{}
	for rows.Next() {
		var r model.RiskRule
		if err := rows.Scan(&r.ID, &r.Port, &r.Service, &r.Severity, &r.Label, &r.Enabled, &r.VersionBelow); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateRiskRule(r model.RiskRule) (model.RiskRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Severity == "" {
		r.Severity = "warning"
	}
	res, err := s.db.Exec(`INSERT INTO risk_rules (port, service, severity, label, enabled, version_below) VALUES (?, ?, ?, ?, ?, ?)`,
		r.Port, r.Service, r.Severity, r.Label, r.Enabled, r.VersionBelow)
	if err != nil {
		return model.RiskRule{}, err
	}
	r.ID, err = res.LastInsertId()
	return r, err
}

// UpdateRiskRule applies whichever fields are non-nil, leaving the rest of
// the rule untouched. versionBelow uses a non-nil *string the same way the
// others do — pass a pointer to "" to explicitly clear a previously-set
// threshold back to "always matches on port/service alone".
func (s *Store) UpdateRiskRule(id int64, port *int, label, severity, service, versionBelow *string, enabled *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sets []string
	var args []any
	if port != nil {
		sets = append(sets, "port = ?")
		args = append(args, *port)
	}
	if label != nil {
		sets = append(sets, "label = ?")
		args = append(args, *label)
	}
	if severity != nil {
		sets = append(sets, "severity = ?")
		args = append(args, *severity)
	}
	if service != nil {
		sets = append(sets, "service = ?")
		args = append(args, *service)
	}
	if versionBelow != nil {
		sets = append(sets, "version_below = ?")
		args = append(args, *versionBelow)
	}
	if enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, *enabled)
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.Exec(`UPDATE risk_rules SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *Store) DeleteRiskRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM risk_rules WHERE id = ?`, id)
	return err
}
