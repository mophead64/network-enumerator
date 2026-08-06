package model

import "time"

type Subnet struct {
	ID           int64     `json:"id"`
	CIDR         string    `json:"cidr"`
	Name         string    `json:"name"`
	Source       string    `json:"source"` // "auto" | "manual"
	Iface        string    `json:"iface,omitempty"`
	DiscoveredAt time.Time `json:"discoveredAt"`
	LastScanAt   time.Time `json:"lastScanAt,omitempty"`
	Enabled      bool      `json:"enabled"`

	// Hidden suppresses this subnet's hosts from the host list, graph, and
	// dashboard counts (e.g. the local Docker/management subnet a scan picks
	// up automatically but that isn't actually in scope). The subnet is
	// still scanned and its data kept — hiding is a view filter, not a
	// disable switch.
	Hidden bool `json:"hidden"`
}

type Host struct {
	ID        int64     `json:"id"`
	SubnetID  int64     `json:"subnetId"`
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	Status    string    `json:"status"` // "up" | "down"
	Source    string    `json:"source"` // "auto" | "manual"
	Notes     string    `json:"notes,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	IsNew     bool      `json:"isNew"`
	MissCount int       `json:"-"`
	Tags      []Tag     `json:"tags,omitempty"`
	Ports     []Port    `json:"ports,omitempty"`

	// Suspect flags a host whose MAC address is shared with an unusually
	// large number of other hosts on the same subnet — a strong signal
	// that a single device (a router doing proxy ARP, a captive network,
	// etc.) is answering for addresses that aren't real distinct hosts,
	// rather than that many real devices actually exist.
	Suspect       bool   `json:"suspect,omitempty"`
	SuspectReason string `json:"suspectReason,omitempty"`

	// RiskLevel/RiskReasons are computed from the configured RiskRules
	// against this host's open ports: "critical" | "warning" | "info" | "".
	RiskLevel   string   `json:"riskLevel,omitempty"`
	RiskReasons []string `json:"riskReasons,omitempty"`

	// Acknowledged means a user has reviewed this host's current priority
	// flag and exempted it from "priority" triage views. It's cleared
	// automatically the moment a new port is discovered open on the host,
	// since that's a material change to what was reviewed.
	Acknowledged bool `json:"acknowledged"`
}

// RiskRule flags hosts running a risky/legacy service so they can be
// triaged and hardened first. Matched against a host's open ports by port
// number and, optionally, a substring match against the detected service
// name.
type RiskRule struct {
	ID       int64  `json:"id"`
	Port     int    `json:"port"`
	Service  string `json:"service,omitempty"` // substring match on detected service name; empty matches any service on Port
	Severity string `json:"severity"`          // "critical" | "warning" | "info"
	Label    string `json:"label"`
	Enabled  bool   `json:"enabled"`

	// VersionBelow, if set, additionally requires the matched port's detected
	// Version to be older than this before the rule fires — e.g. "8.0" flags
	// OpenSSH 7.x but not 8.x or newer. Compared numerically component by
	// component (see versionLess), not as a strict semver parse, since real
	// service version strings ("7.4", "2.4.41", "8.9p1") vary too much for
	// that. Only ever populated by nmap's version detection — a rule with a
	// VersionBelow set simply never matches a port scanned by the built-in
	// TCP prober, which has no version data to compare.
	VersionBelow string `json:"versionBelow,omitempty"`
}

type Port struct {
	ID       int64  `json:"id"`
	HostID   int64  `json:"hostId"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp"
	State    string `json:"state"`    // "open"
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`

	// Product/Version are structured service-version metadata from nmap's
	// version detection (-sV) — e.g. Product "OpenSSH", Version "7.4". Only
	// populated when the scan method is nmap; the built-in TCP prober has no
	// equivalent capability, so these stay empty on that path. Used by risk
	// rules to flag outdated versions of a service, not just the port/name.
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`

	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	IsNew     bool      `json:"isNew"`
}

type Tag struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type Event struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"` // new_subnet, new_host, host_down, host_up, new_port, port_closed, host_removed, priority_reflag
	Message   string    `json:"message"`
	EntityID  int64     `json:"entityId,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type ScanStatus struct {
	Running      bool      `json:"running"`
	Deep         bool      `json:"deep"` // true while the currently-running cycle is scanning every port, not just CommonPorts
	LastStarted  time.Time `json:"lastStarted,omitempty"`
	LastFinished time.Time `json:"lastFinished,omitempty"`
	HostsScanned int       `json:"hostsScanned"`
	IntervalSec  int       `json:"intervalSec"`
}
