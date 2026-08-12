package discovery

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"network-enumerator/internal/model"
	"network-enumerator/internal/store"
)

type Config struct {
	Interval          time.Duration
	HostConcurrency   int
	PortConcurrency   int
	DiscoveryTimeout  time.Duration
	PortTimeout       time.Duration
	DNSTimeout        time.Duration
	MissThreshold     int // consecutive misses before a host is marked down
	AutoDiscoverLocal bool
}

func DefaultConfig() Config {
	return Config{
		Interval:          60 * time.Second,
		HostConcurrency:   128,
		PortConcurrency:   24,
		DiscoveryTimeout:  600 * time.Millisecond,
		PortTimeout:       500 * time.Millisecond,
		DNSTimeout:        500 * time.Millisecond,
		MissThreshold:     3,
		AutoDiscoverLocal: true,
	}
}

// ScanMode forces a specific technique for a manually triggered scan cycle
// (see TriggerQuickScanAll/TriggerMassScanAll/TriggerDeepScanAll),
// regardless of the configured Settings scan-method preference. The zero
// value "" is the regular automatic/system-triggered cycle (a new subnet
// was added, data was imported, the interval timer fired, ...), which keeps
// respecting that preference exactly as before — only an explicit mode
// bypasses it.
type ScanMode string

const (
	ScanModeQuick      ScanMode = "quick" // built-in TCP/ICMP prober, common ports — fast, doesn't need nmap
	ScanModeMass       ScanMode = "mass"  // nmap forced, common ports — broad nmap sweep across every host
	ScanModeDeep       ScanMode = "deep"  // nmap forced, all 65535 ports — thorough but slow
	ScanModeReverseDNS ScanMode = "dns"   // dnsrecon/dig -x only, no ping/TCP/ARP — see scanSubnetReverseDNS
)

type Scanner struct {
	st     *store.Store
	cfg    Config
	pinger *ICMPPinger
	notify func(model.Event)

	statusMu sync.Mutex
	status   model.ScanStatus

	trigger        chan struct{} // unforced: respects the configured scan-method setting
	triggerQuick   chan struct{}
	triggerMass    chan struct{}
	triggerDeep    chan struct{}
	triggerReverse chan struct{}

	deepScanMu   sync.Mutex
	deepScanning map[int64]bool // hostID -> a deep scan is currently running for it
}

func NewScanner(st *store.Store, cfg Config, notify func(model.Event)) *Scanner {
	pinger, ok := NewICMPPinger()
	if !ok {
		log.Printf("icmp: no privilege for raw or unprivileged ICMP sockets; falling back to TCP-only host discovery")
		pinger = nil
	}
	return &Scanner{
		st:             st,
		cfg:            cfg,
		pinger:         pinger,
		notify:         notify,
		status:         model.ScanStatus{IntervalSec: int(cfg.Interval.Seconds())},
		trigger:        make(chan struct{}, 1),
		triggerQuick:   make(chan struct{}, 1),
		triggerMass:    make(chan struct{}, 1),
		triggerDeep:    make(chan struct{}, 1),
		triggerReverse: make(chan struct{}, 1),
		deepScanning:   make(map[int64]bool),
	}
}

func (s *Scanner) Close() {
	if s.pinger != nil {
		s.pinger.Close()
	}
}

func (s *Scanner) Status() model.ScanStatus {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	return s.status
}

// TriggerNow requests an immediate scan cycle without waiting for the
// interval timer — the regular, unforced cycle that still respects the
// configured scan-method setting. Used for system-triggered rescans (a
// subnet was just added, data was imported, ...), not the user-facing
// Quick/Mass/Deep actions. Non-blocking: if a scan is already queued to
// start, this is a no-op.
func (s *Scanner) TriggerNow() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// TriggerQuickScanAll requests an immediate scan cycle that forces the
// built-in TCP/ICMP prober (common ports), regardless of the configured
// scan-method setting — the "Quick scan" action. Non-blocking: if one is
// already queued, this is a no-op.
func (s *Scanner) TriggerQuickScanAll() {
	select {
	case s.triggerQuick <- struct{}{}:
	default:
	}
}

// TriggerMassScanAll requests an immediate scan cycle that forces nmap
// (common ports) across every host, regardless of the configured
// scan-method setting — the "Mass scan" action. Non-blocking: if one is
// already queued, this is a no-op.
func (s *Scanner) TriggerMassScanAll() {
	select {
	case s.triggerMass <- struct{}{}:
	default:
	}
}

// TriggerDeepScanAll requests an immediate scan cycle that forces nmap
// against every TCP port (1-65535) on every host, instead of the curated
// CommonPorts list a normal cycle uses — the "Deep scan" action. Much
// slower across a whole subnet than DeepScanHost is for one host — it's
// still bounded by the usual host/port concurrency, so it won't run away,
// but it can take a long time on a large network. Non-blocking: if one is
// already queued, this is a no-op.
func (s *Scanner) TriggerDeepScanAll() {
	select {
	case s.triggerDeep <- struct{}{}:
	default:
	}
}

// TriggerReverseDNSScanAll requests an immediate scan cycle that sweeps
// every address in every subnet for a PTR record (dnsrecon if installed,
// else dig -x per address) instead of the usual ping/TCP/ARP discovery —
// the "Reverse DNS scan" action. See scanSubnetReverseDNS. Non-blocking: if
// one is already queued, this is a no-op.
func (s *Scanner) TriggerReverseDNSScanAll() {
	select {
	case s.triggerReverse <- struct{}{}:
	default:
	}
}

func (s *Scanner) Run(ctx context.Context) {
	s.runOnce(ctx, "")
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx, "")
		case <-s.trigger:
			s.runOnce(ctx, "")
			ticker.Reset(s.cfg.Interval)
		case <-s.triggerQuick:
			s.runOnce(ctx, ScanModeQuick)
			ticker.Reset(s.cfg.Interval)
		case <-s.triggerMass:
			s.runOnce(ctx, ScanModeMass)
			ticker.Reset(s.cfg.Interval)
		case <-s.triggerDeep:
			s.runOnce(ctx, ScanModeDeep)
			ticker.Reset(s.cfg.Interval)
		case <-s.triggerReverse:
			s.runOnce(ctx, ScanModeReverseDNS)
			ticker.Reset(s.cfg.Interval)
		}
	}
}

func (s *Scanner) emit(evType, message string, entityID int64) {
	ev, err := s.st.AddEvent(evType, message, entityID)
	if err != nil {
		log.Printf("event store error: %v", err)
		return
	}
	log.Printf("[%s] %s", evType, message)
	if s.notify != nil {
		s.notify(ev)
	}
}

// runOnce executes one scan cycle across every enabled subnet. mode is ""
// for the regular automatic/system-triggered cycle (respects the configured
// scan-method setting), or one of ScanModeQuick/ScanModeMass/ScanModeDeep/
// ScanModeReverseDNS to force a specific technique for a manually triggered
// cycle — see ScanMode.
func (s *Scanner) runOnce(ctx context.Context, mode ScanMode) {
	if mode != "" {
		log.Printf("scan: starting %s cycle", mode)
	} else {
		log.Printf("scan: starting cycle")
	}
	s.statusMu.Lock()
	s.status.Running = true
	s.status.Mode = string(mode)
	s.status.LastStarted = time.Now()
	s.status.HostsScanned = 0
	s.statusMu.Unlock()

	if s.cfg.AutoDiscoverLocal {
		locals, err := LocalSubnets()
		if err != nil {
			log.Printf("interface discovery error: %v", err)
		}
		for _, l := range locals {
			id, created, err := s.st.UpsertAutoSubnet(l.CIDR, "", l.Iface)
			if err != nil {
				log.Printf("upsert subnet %s: %v", l.CIDR, err)
				continue
			}
			if created {
				s.emit("new_subnet", fmt.Sprintf("Discovered local subnet %s on %s", l.CIDR, l.Iface), id)
			}
		}
	}

	subnets, err := s.st.ListSubnets()
	if err != nil {
		log.Printf("list subnets: %v", err)
	}

	// Subnets are scanned concurrently with each other (each already bounds
	// its own per-host concurrency internally) so that one large or slow
	// subnet can't starve the others of a turn.
	var total int64
	var wg sync.WaitGroup
	for _, sn := range subnets {
		if !sn.Enabled {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		wg.Add(1)
		go func(sn model.Subnet) {
			defer wg.Done()
			n := s.scanSubnet(ctx, sn, mode)
			atomic.AddInt64(&total, int64(n))
		}(sn)
	}
	wg.Wait()

	s.statusMu.Lock()
	s.status.Running = false
	s.status.Mode = ""
	s.status.LastFinished = time.Now()
	s.status.HostsScanned = int(total)
	s.statusMu.Unlock()
	log.Printf("scan: cycle finished, %d hosts seen", total)
}

// effectiveScanMethod resolves the configured scan-method preference against
// nmap's actual availability on this host: "auto" uses nmap when present,
// falling back to the built-in TCP/ICMP prober otherwise; "nmap"/"tcp" force
// one or the other. A forced "nmap" preference without the binary installed
// still falls back (with a log line) rather than silently scanning nothing.
// Only consulted for the regular, unforced cycle (mode == "") — see
// resolveScanMethod.
func (s *Scanner) effectiveScanMethod() (method, nmapPath string) {
	pref, err := s.st.GetScanMethod()
	if err != nil {
		log.Printf("read scan method setting: %v", err)
		pref = store.ScanMethodAuto
	}
	if pref == store.ScanMethodTCP {
		return "tcp", ""
	}
	path, available := NmapPath()
	if !available {
		if pref == store.ScanMethodNmap {
			log.Printf("scan method set to nmap, but the nmap binary isn't on PATH; using built-in TCP/ICMP scanning for this cycle")
		}
		return "tcp", ""
	}
	return "nmap", path
}

// resolveScanMethod picks which technique a cycle actually uses: an
// explicit mode forces tcp (ScanModeQuick) or nmap (ScanModeMass/
// ScanModeDeep) outright; mode == "" (the regular automatic/system-
// triggered cycle) falls back to the configured Settings scan-method
// preference via effectiveScanMethod, same as before ScanMode existed. The
// API layer checks nmap's availability before ever queuing a mass/deep
// trigger, but this still falls back to tcp (with a log line) rather than
// scanning nothing in the unlikely case the binary vanishes in between.
func (s *Scanner) resolveScanMethod(mode ScanMode) (method, nmapPath string) {
	switch mode {
	case ScanModeQuick:
		return "tcp", ""
	case ScanModeMass, ScanModeDeep:
		path, available := NmapPath()
		if !available {
			log.Printf("%s scan requested but nmap isn't on PATH; using built-in TCP/ICMP scanning for this cycle", mode)
			return "tcp", ""
		}
		return "nmap", path
	default:
		return s.effectiveScanMethod()
	}
}

func (s *Scanner) scanSubnet(ctx context.Context, sn model.Subnet, mode ScanMode) int {
	if mode == ScanModeReverseDNS {
		return s.scanSubnetReverseDNS(ctx, sn)
	}
	deep := mode == ScanModeDeep
	if method, nmapPath := s.resolveScanMethod(mode); method == "nmap" {
		return s.scanSubnetNmap(ctx, sn, deep, nmapPath)
	}
	return s.scanSubnetTCP(ctx, sn, deep)
}

// scanSubnetReverseDNS is the "Reverse DNS scan" action: skips ping/TCP/ARP
// discovery entirely and sweeps every address in sn for a PTR record (via
// dnsrecon if installed, else dig -x per address — see reverseDNSSweep),
// port-scanning (common ports) whatever it finds to try to confirm it up —
// exactly the passive DNS-only pass a regular cycle already runs for
// addresses it couldn't otherwise reach (see scanUnconfirmedByDNS), just
// run here against the whole subnet on demand instead of only what that
// cycle happened to miss.
//
// Deliberately does not sweep for "missing" hosts the way scanSubnetTCP/
// scanSubnetNmap do: most real hosts have no PTR record at all, so treating
// "no PTR hit this cycle" as evidence a host went away would flip
// previously-confirmed hosts to "down" for no real reason. A reverse DNS
// scan can only add information, never take a host's status away.
func (s *Scanner) scanSubnetReverseDNS(ctx context.Context, sn model.Subnet) int {
	ips, err := ExpandIPv4(sn.CIDR)
	if err != nil {
		log.Printf("expand %s: %v", sn.CIDR, err)
		return 0
	}
	candidates := make([]string, len(ips))
	for i, ip := range ips {
		candidates[i] = ip.String()
	}

	confirmed := s.scanUnconfirmedByDNS(ctx, candidates, sn, false)

	if err := s.st.TouchSubnetScan(sn.ID); err != nil {
		log.Printf("touch subnet scan: %v", err)
	}
	return len(confirmed)
}

// netdiscoverPath resolves whether ARP-based discovery via netdiscover
// should run this cycle: the operator's enabled/disabled preference
// (defaulting to true — use it automatically when present, same default
// nmap gets) combined with whether the binary is actually on PATH.
func (s *Scanner) netdiscoverPath() (path string, ok bool) {
	enabled, err := s.st.GetNetdiscoverEnabled()
	if err != nil {
		log.Printf("read netdiscover setting: %v", err)
		enabled = true
	}
	if !enabled {
		return "", false
	}
	return NetdiscoverPath()
}

// netdiscoverAugment runs an ARP sweep of sn via netdiscover and returns
// whatever it found, keyed by IP. It's only meaningful for subnets this host
// is directly attached to (sn.Iface, set by LocalSubnets() for auto-detected
// local subnets) — ARP doesn't route, so netdiscover has nothing to offer on
// a routed or manually-added subnet reached through a gateway. Failures are
// logged and swallowed: netdiscover is a supplementary source on top of the
// built-in TCP/ICMP prober, never the only way a host gets found.
func (s *Scanner) netdiscoverAugment(ctx context.Context, sn model.Subnet) map[string]NetdiscoverHost {
	if sn.Iface == "" {
		return nil
	}
	path, ok := s.netdiscoverPath()
	if !ok {
		return nil
	}
	const timeout = 20 * time.Second
	hosts, err := RunNetdiscover(ctx, path, sn.Iface, sn.CIDR, timeout)
	if err != nil {
		log.Printf("netdiscover %s: %v", sn.CIDR, err)
		return nil
	}
	found := make(map[string]NetdiscoverHost, len(hosts))
	for _, h := range hosts {
		found[h.IP] = h
	}
	return found
}

// unseenIPStrings returns every address in ips whose string form isn't a key
// in seen — the candidate list scanUnconfirmedByDNS sweeps with dig -x.
func unseenIPStrings(ips []net.IP, seen map[string]bool) []string {
	out := make([]string, 0, len(ips)-len(seen))
	for _, ip := range ips {
		if s := ip.String(); !seen[s] {
			out = append(out, s)
		}
	}
	return out
}

func sliceToSet(ips []string) map[string]bool {
	set := make(map[string]bool, len(ips))
	for _, ip := range ips {
		set[ip] = true
	}
	return set
}

// digPath resolves whether dig-based reverse-DNS discovery should run this
// cycle — just binary presence on PATH, same as NmapPath/NetdiscoverPath.
func (s *Scanner) digPath() (string, bool) {
	return DigPath()
}

// reverseDNSSweepTimeout bounds both the dnsrecon batch sweep and the
// per-address dig -x fallback (dig itself is bounded separately, per call,
// by cfg.DNSTimeout — this is the budget for the whole subnet).
const reverseDNSSweepTimeout = 45 * time.Second

// dnsOnlyResult is what scanUnconfirmedByDNS found and confirmed for one
// candidate address.
type dnsOnlyResult struct {
	hostID    int64
	openPorts map[int]bool
}

// scanUnconfirmedByDNS is the "additional enumeration task" a reverse-DNS
// sweep adds on top of ping/TCP/ARP discovery: for candidates — addresses
// none of those found alive — see whether DNS knows about them via a PTR
// record (via reverseDNSSweep). A PTR hit is a much weaker signal than a
// live probe: it's a static DNS entry that persists whether or not the
// device behind it is even powered on, so finding one is never proof a host
// is up. Each hit is recorded via UpsertUnconfirmedHost (status "unknown",
// never "up"/"down") and still port-scanned anyway, since a TCP connect
// probe doesn't need ICMP to succeed — only an actual open port is real
// confirmation, at which point the host is promoted to "up" and returned
// here so the caller can fold it into its normal alive/seen bookkeeping
// instead of scanning its ports a second time.
func (s *Scanner) scanUnconfirmedByDNS(ctx context.Context, candidates []string, sn model.Subnet, deep bool) map[string]dnsOnlyResult {
	hostnames := s.reverseDNSSweep(ctx, sn, candidates)
	if len(hostnames) == 0 {
		return nil
	}

	confirmed := make(map[string]dnsOnlyResult)
	var mu sync.Mutex
	sem := make(chan struct{}, s.cfg.HostConcurrency)
	var wg sync.WaitGroup
	for ip, hostname := range hostnames {
		ip, hostname := ip, hostname
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hostID, isNew, err := s.st.UpsertUnconfirmedHost(sn.ID, ip, hostname)
			if err != nil {
				log.Printf("upsert unconfirmed host %s: %v", ip, err)
				return
			}
			if isNew {
				s.emit("new_host", fmt.Sprintf(
					"Reverse DNS found %s (%s) — no ping/TCP/ARP response, not yet confirmed up; watching for an open port",
					ip, hostname), hostID)
			}

			openPorts := s.scanPorts(hostID, ip, deep)
			if len(openPorts) == 0 {
				return
			}
			if err := s.st.ConfirmHostUp(hostID); err != nil {
				log.Printf("confirm host up %s: %v", ip, err)
				return
			}
			mu.Lock()
			confirmed[ip] = dnsOnlyResult{hostID: hostID, openPorts: openPorts}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return confirmed
}

// reverseDNSSweep resolves hostnames for candidates using whichever
// reverse-DNS tool is available, preferring dnsrecon's single-process range
// sweep (see RunDnsrecon) over spawning `dig -x` once per candidate address
// when both happen to be installed — a /24 with nothing else discovered is
// 254 dig subprocesses against one dnsrecon invocation. Falls back to dig -x
// (per-candidate, so it still works on a handful of otherwise-silent
// addresses rather than the whole subnet) when dnsrecon isn't on PATH or
// its sweep fails, and returns nil if neither tool is available.
func (s *Scanner) reverseDNSSweep(ctx context.Context, sn model.Subnet, candidates []string) map[string]string {
	if len(candidates) == 0 {
		return nil
	}

	if path, ok := DnsreconPath(); ok {
		results, err := RunDnsrecon(ctx, path, sn.CIDR, reverseDNSSweepTimeout)
		if err != nil {
			log.Printf("dnsrecon %s: %v — falling back to dig -x per address", sn.CIDR, err)
		} else {
			candSet := sliceToSet(candidates)
			out := make(map[string]string, len(results))
			for ip, names := range results {
				if candSet[ip] && len(names) > 0 {
					out[ip] = names[0]
				}
			}
			return out
		}
	}

	digPath, ok := s.digPath()
	if !ok {
		return nil
	}
	out := make(map[string]string)
	var mu sync.Mutex
	sem := make(chan struct{}, s.cfg.HostConcurrency)
	var wg sync.WaitGroup
	for _, ip := range candidates {
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if hostname := ReverseDNSDig(ctx, digPath, ip, s.cfg.DNSTimeout); hostname != "" {
				mu.Lock()
				out[ip] = hostname
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// nmapCycleState is scanSubnetNmap's per-cycle bookkeeping, shared across
// every host's goroutine (guarded by mu) as each finishes recording itself.
type nmapCycleState struct {
	mu             sync.Mutex
	arpTable       map[string]string // one kernel-table read, reused for every host this cycle
	hostIDs        map[string]int64
	seen           map[string]bool
	macCounts      map[string]int
	unionOpenPorts map[int]bool
	pingOnlyCount  int64
}

// foldDNSConfirmed merges one scanUnconfirmedByDNS result into st. The host
// is already recorded (status promoted "unknown" -> "up") and port-scanned
// by scanUnconfirmedByDNS itself — this only adds what that pass couldn't
// supply (a MAC, if the kernel ARP table happens to have one) and folds its
// open ports into the union nmap enriches, without probing or port-scanning
// the host a second time.
func (s *Scanner) foldDNSConfirmed(sn model.Subnet, ip string, res dnsOnlyResult, st *nmapCycleState) {
	mac := st.arpTable[ip]
	if mac != "" {
		if _, _, err := s.st.UpsertHost(sn.ID, ip, mac, "", ""); err != nil {
			log.Printf("update host mac %s: %v", ip, err)
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.hostIDs[ip] = res.hostID
	st.seen[ip] = true
	if mac != "" {
		st.macCounts[mac]++
	}
	for port := range res.openPorts {
		st.unionOpenPorts[port] = true
	}
}

// discoverAliveHosts fans the same fast TCP/ICMP probe scanSubnetTCP uses
// out across every address in cidr and returns the ones that answered.
// scanSubnetNmap runs this first and hands nmap only the resulting list
// (with -Pn) rather than letting nmap sweep the whole range itself — nmap's
// own host-discovery is noticeably slower than the built-in prober's,
// especially once -sV's per-port version probes are added on top, so
// splitting the two keeps a scan cycle fast even though nmap is doing the
// heavier lifting for port/version detail.
func (s *Scanner) discoverAliveHosts(cidr string) ([]string, error) {
	ips, err := ExpandIPv4(cidr)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var alive []string
	sem := make(chan struct{}, s.cfg.HostConcurrency)
	var wg sync.WaitGroup
	for _, ip := range ips {
		ipStr := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.isAlive(ipStr) {
				mu.Lock()
				alive = append(alive, ipStr)
				mu.Unlock()
			}
		}(ipStr)
	}
	wg.Wait()
	return alive, nil
}

// discoverAliveHostsAllSources is discoverAliveHosts plus the two weaker
// discovery signals scanSubnetNmap unions on top of it: netdiscover's ARP
// sweep, and a dig -x reverse-DNS sweep of whatever's left unseen by either
// of those. The dig -x pass runs *before* any "nothing found" bailout so a
// subnet with zero ping/TCP/ARP responses but a DNS-confirmed host isn't
// reported as fully dark. Returns the combined alive list, netdiscover's
// finds (for MAC/vendor enrichment), and dig's confirmed-by-open-port finds
// (already recorded and port-scanned, so the caller shouldn't redo either).
func (s *Scanner) discoverAliveHostsAllSources(ctx context.Context, sn model.Subnet, deep bool) (alive []string, ndHosts map[string]NetdiscoverHost, dnsConfirmed map[string]dnsOnlyResult, err error) {
	alive, err = s.discoverAliveHosts(sn.CIDR)
	if err != nil {
		return nil, nil, nil, err
	}

	// ARP-only hosts (filtered ICMP/TCP but still answering ARP) never show
	// up in the built-in prober's alive list, so netdiscover's finds are
	// unioned in here rather than only used to enrich hosts already found.
	ndHosts = s.netdiscoverAugment(ctx, sn)
	aliveSet := sliceToSet(alive)
	for ip := range ndHosts {
		if !aliveSet[ip] {
			alive = append(alive, ip)
			aliveSet[ip] = true
		}
	}

	allIPs, expErr := ExpandIPv4(sn.CIDR)
	if expErr != nil {
		log.Printf("expand %s: %v", sn.CIDR, expErr)
		return alive, ndHosts, nil, nil
	}
	dnsConfirmed = s.scanUnconfirmedByDNS(ctx, unseenIPStrings(allIPs, sliceToSet(alive)), sn, deep)
	for ip := range dnsConfirmed {
		alive = append(alive, ip)
	}
	return alive, ndHosts, dnsConfirmed, nil
}

// scanSubnetNmap discovers which hosts in sn are up and which ports they
// have open using the fast built-in TCP/ICMP prober — the same one
// scanSubnetTCP uses — then hands nmap only the ports that step already
// confirmed open, to enrich with product/version detail. nmap never decides
// open-vs-closed here: it costs meaningfully more time per port than a plain
// connect probe, and per --host-timeout can silently return zero results for
// a whole host if it doesn't finish in time (both measured directly —
// see the comments below and in RunNmap). Scoping nmap down to a known-open
// port list, rather than sweeping the full CommonPorts/all-65535 range
// itself, is also just less work for it to do.
func (s *Scanner) scanSubnetNmap(ctx context.Context, sn model.Subnet, deep bool, nmapPath string) int {
	// --version-intensity trades detection thoroughness for speed. Measured
	// against a real host with several open, non-trivially-identified
	// services: intensity 3 identified every one of them exactly as well as
	// nmap's own default (7) — same product/version — in a fifth of the
	// time (34s vs 161s); the extra time at higher intensities went into
	// obscure probes that produced no additional matches. Regular cycles
	// stay fast with a low intensity; deep scans (already understood by
	// users as slow but thorough) get nmap's fuller default (0 = omit the
	// flag). hostTimeout needs real headroom above the plain-scan budget
	// regardless — if it's hit mid-host, nmap's XML omits that host's
	// <ports> section entirely, a silently empty result rather than a
	// partial one.
	hostTimeout := 90 * time.Second
	versionIntensity := 3
	if deep {
		hostTimeout = 10 * time.Minute
		versionIntensity = 0
	}

	alive, ndHosts, dnsConfirmed, err := s.discoverAliveHostsAllSources(ctx, sn, deep)
	if err != nil {
		log.Printf("expand %s: %v", sn.CIDR, err)
		return 0
	}
	if err := s.st.TouchSubnetScan(sn.ID); err != nil {
		log.Printf("touch subnet scan: %v", err)
	}

	if len(alive) == 0 {
		s.emitHostDownEvents(sn, map[string]bool{})
		return 0
	}

	// Record every host as up (MAC/hostname from ARP/reverse-DNS) and find
	// its open ports with the built-in TCP prober, concurrently across hosts
	// same as scanSubnetTCP. This is what actually determines port state —
	// nmap below only adds product/version on top of it. Hosts and their
	// ports land in the UI within seconds of being probed, rather than
	// waiting on nmap's much slower enrichment pass to finish first.
	st := &nmapCycleState{
		arpTable:       ARPTable(),
		hostIDs:        make(map[string]int64, len(alive)),
		seen:           make(map[string]bool, len(alive)),
		macCounts:      make(map[string]int),
		unionOpenPorts: make(map[int]bool),
	}
	sem := make(chan struct{}, s.cfg.HostConcurrency)
	var wg sync.WaitGroup

	for _, ip := range alive {
		ip := ip
		if res, ok := dnsConfirmed[ip]; ok {
			s.foldDNSConfirmed(sn, ip, res, st)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			mac := st.arpTable[ip]
			vendor := ""
			if nd, ok := ndHosts[ip]; ok {
				if mac == "" {
					mac = nd.MAC
				}
				vendor = nd.Vendor
			}
			hostID, err := s.recordHost(sn.ID, ip, mac, s.reverseDNS(ip), vendor)
			if err != nil {
				log.Printf("upsert host %s: %v", ip, err)
				return
			}
			openPorts := s.scanPorts(hostID, ip, deep)

			st.mu.Lock()
			defer st.mu.Unlock()
			st.hostIDs[ip] = hostID
			st.seen[ip] = true
			if mac != "" {
				st.macCounts[mac]++
			}
			if len(openPorts) == 0 {
				st.pingOnlyCount++
			}
			for port := range openPorts {
				st.unionOpenPorts[port] = true
			}
		}()
	}
	wg.Wait()

	s.checkPingOnlyAnomaly(sn, len(st.seen), st.pingOnlyCount)
	s.checkDuplicateMACAnomaly(sn, st.macCounts)
	s.emitHostDownEvents(sn, st.seen)

	if len(st.unionOpenPorts) == 0 {
		return len(st.seen) // nothing open anywhere on this subnet to enrich
	}
	enrichPorts := make([]int, 0, len(st.unionOpenPorts))
	for port := range st.unionOpenPorts {
		enrichPorts = append(enrichPorts, port)
	}

	log.Printf("nmap enrichment: starting for %s — %d open port(s) across %d host(s)", sn.CIDR, len(enrichPorts), len(st.seen))
	nmapHosts, err := RunNmap(ctx, nmapPath, alive, enrichPorts, hostTimeout, versionIntensity)
	if err != nil {
		// Port state is already fully recorded above from the built-in TCP
		// scan — only the product/version enrichment is missing this cycle.
		log.Printf("nmap enrichment of %s failed: %v — ports are recorded from the built-in scan, just without product/version detail this cycle", sn.CIDR, err)
		return len(st.seen)
	}
	enriched := 0
	for _, h := range nmapHosts {
		hostID, ok := st.hostIDs[h.IP]
		if !ok {
			continue
		}
		// nmap's ARP host-discovery (used implicitly for local targets) reports
		// MAC/vendor in its XML output; UpsertHost only touches non-empty
		// fields, so this only ever fills in what ARPTable()/netdiscover missed
		// above, never overwrites a value they already found.
		if h.MAC != "" || h.Vendor != "" {
			if _, _, err := s.st.UpsertHost(sn.ID, h.IP, h.MAC, "", h.Vendor); err != nil {
				log.Printf("update host mac/vendor %s: %v", h.IP, err)
			}
		}
		for _, p := range h.Ports {
			s.recordOpenPort(hostID, h.IP, p.Port, p.Service, p.Banner, p.Product, p.Version)
			enriched++
		}
	}
	log.Printf("nmap enrichment: finished for %s — %d port(s) enriched across %d host(s)", sn.CIDR, enriched, len(nmapHosts))

	return len(st.seen)
}

func (s *Scanner) scanSubnetTCP(ctx context.Context, sn model.Subnet, deep bool) int {
	ips, err := ExpandIPv4(sn.CIDR)
	if err != nil {
		log.Printf("expand %s: %v", sn.CIDR, err)
		return 0
	}

	// ARP-only hosts (filtered ICMP/TCP but still answering ARP) never pass
	// isAlive() below; netdiscover's finds let probeAndRecord count them
	// anyway, using its MAC/vendor since ARPTable() alone can't supply either.
	ndHosts := s.netdiscoverAugment(ctx, sn)

	seen := make(map[string]bool)
	var seenMu sync.Mutex
	var macMu sync.Mutex
	macCounts := make(map[string]int) // mac -> number of distinct IPs seen answering as it this cycle
	var pingOnlyCount int64           // alive with zero open ports — see checkPingOnlyAnomaly
	sem := make(chan struct{}, s.cfg.HostConcurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		ipStr := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()
			alive, hadOpenPort, mac := s.probeAndRecord(ctx, sn, ipStr, deep, ndHosts)
			if !alive {
				return
			}
			seenMu.Lock()
			seen[ipStr] = true
			seenMu.Unlock()
			if !hadOpenPort {
				atomic.AddInt64(&pingOnlyCount, 1)
			}
			if mac != "" {
				macMu.Lock()
				macCounts[mac]++
				macMu.Unlock()
			}
		}(ipStr)
	}
	wg.Wait()

	// dig -x sweep: a second pass over whatever ping/TCP/ARP above found
	// nothing for at all. See scanUnconfirmedByDNS for why a PTR hit alone
	// never promotes a host into seen/up the way the loop above does.
	for ip := range s.scanUnconfirmedByDNS(ctx, unseenIPStrings(ips, seen), sn, deep) {
		seen[ip] = true // confirmed via an open port — not "ping-only", so pingOnlyCount is untouched
	}

	if err := s.st.TouchSubnetScan(sn.ID); err != nil {
		log.Printf("touch subnet scan: %v", err)
	}

	s.checkPingOnlyAnomaly(sn, len(seen), pingOnlyCount)
	s.checkDuplicateMACAnomaly(sn, macCounts)
	s.emitHostDownEvents(sn, seen)

	return len(seen)
}

// checkDuplicateMACAnomaly flags subnets where a single MAC address answered
// for an unusually large number of IPs in this scan cycle. A real subnet has
// one MAC per device; seeing one MAC answer for dozens of addresses means a
// single device (a router doing proxy ARP, a captive/guest network, some
// mesh Wi-Fi setups) is responding on behalf of addresses that aren't real
// distinct hosts — the classic cause of a scan that "finds" far more hosts
// than actually exist on the network, without needing Docker/NAT to be
// involved at all. Matches store.suspectMACThreshold so the event and the
// per-host "suspect" badge agree on what counts as anomalous.
func (s *Scanner) checkDuplicateMACAnomaly(sn model.Subnet, macCounts map[string]int) {
	const suspectMACThreshold = 8
	for mac, count := range macCounts {
		if count >= suspectMACThreshold {
			s.emit("scan_anomaly", fmt.Sprintf(
				"%s: MAC %s answered for %d different addresses in this scan — that's almost certainly one device (e.g. a router doing proxy ARP) responding for addresses that aren't real hosts, not %d separate devices. Affected hosts are marked \"suspect\" in the UI; verify manually or hide them via the suspect filter.",
				sn.CIDR, mac, count, count), sn.ID)
		}
	}
}

// checkPingOnlyAnomaly flags subnets where most discovered hosts responded
// to ping but had zero open ports. A NAT/virtualization layer between us
// and the target network can fake ICMP echo replies for addresses that
// don't actually exist (observed running this exact scanner inside Docker
// Desktop / Rancher Desktop on macOS, which appears to loop outbound pings
// back as replies rather than dropping unroutable ones) — that looks
// identical to "most of the subnet is up" but none of those hosts have any
// open port or ARP entry. Flag it rather than silently presenting it as
// real data.
func (s *Scanner) checkPingOnlyAnomaly(sn model.Subnet, totalSeen int, pingOnlyCount int64) {
	const anomalyMinHosts = 20
	const anomalyRatio = 0.5
	if totalSeen >= anomalyMinHosts && float64(pingOnlyCount)/float64(totalSeen) > anomalyRatio {
		s.emit("scan_anomaly", fmt.Sprintf(
			"%s: %d of %d discovered hosts responded to ping only, with no open ports — this can mean a NAT or virtualized network layer between here and the target is fabricating replies rather than real hosts being present (common when running inside Docker Desktop/Rancher Desktop on macOS). Verify manually, or run outside Docker for reliable results.",
			sn.CIDR, pingOnlyCount, totalSeen), sn.ID)
	}
}

func (s *Scanner) emitHostDownEvents(sn model.Subnet, seen map[string]bool) {
	wentDown, err := s.st.SweepMissingHosts(sn.ID, seen, s.cfg.MissThreshold)
	if err != nil {
		log.Printf("sweep missing hosts: %v", err)
	}
	for _, hostID := range wentDown {
		h, err := s.st.GetHost(hostID)
		if err != nil {
			continue
		}
		msg := fmt.Sprintf("Host %s stopped responding", h.IP)
		if h.Hostname != "" {
			msg = fmt.Sprintf("Host %s (%s) stopped responding", h.IP, h.Hostname)
		}
		s.emit("host_down", msg, hostID)
	}
}

// probeAndRecord checks whether ip is alive and, if so, records it and
// scans its ports. It returns (alive, hadOpenPort, mac) — hadOpenPort and
// mac are only meaningful when alive is true, and both feed scanSubnet's
// anomaly checks.
func (s *Scanner) probeAndRecord(ctx context.Context, sn model.Subnet, ip string, deep bool, ndHosts map[string]NetdiscoverHost) (bool, bool, string) {
	nd, foundByND := ndHosts[ip]
	if !s.isAlive(ip) && !foundByND {
		return false, false, ""
	}

	hostname := s.reverseDNS(ip)
	mac := ARPTable()[ip]
	if mac == "" {
		mac = nd.MAC
	}

	hostID, err := s.recordHost(sn.ID, ip, mac, hostname, nd.Vendor)
	if err != nil {
		log.Printf("upsert host %s: %v", ip, err)
		return true, false, mac
	}

	openPorts := s.scanPorts(hostID, ip, deep)
	return true, len(openPorts) > 0, mac
}

// recordHost upserts a host and, if it's newly seen, emits the new_host
// event — shared by the built-in prober and the nmap scan path so both
// produce identical events for the same discovery.
func (s *Scanner) recordHost(subnetID int64, ip, mac, hostname, vendor string) (hostID int64, err error) {
	hostID, isNew, err := s.st.UpsertHost(subnetID, ip, mac, hostname, vendor)
	if err != nil {
		return 0, err
	}
	if isNew {
		msg := fmt.Sprintf("New host discovered: %s", ip)
		if hostname != "" {
			msg = fmt.Sprintf("New host discovered: %s (%s)", ip, hostname)
		}
		s.emit("new_host", msg, hostID)
	}
	return hostID, nil
}

// isAlive fans every discovery probe for ip out in parallel and returns as
// soon as the first one comes back positive, rather than trying them one at
// a time. Probing sequentially previously meant a single unreachable host
// could cost len(DiscoveryPorts)+1 whole timeouts (several seconds); most
// addresses in any scanned range are typically unreachable, so that
// multiplied into a scan that could take hours on a large subnet. Run in
// parallel, the wall-clock cost of a dead host is bounded by one timeout.
func (s *Scanner) isAlive(ip string) bool {
	found := make(chan struct{}, 1)
	var wg sync.WaitGroup

	probe := func(fn func() bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if fn() {
				select {
				case found <- struct{}{}:
				default:
				}
			}
		}()
	}

	if s.pinger != nil {
		probe(func() bool { return s.pinger.Ping(ip, s.cfg.DiscoveryTimeout) })
	}
	for _, p := range DiscoveryPorts {
		port := p
		probe(func() bool {
			open, refused := ProbeTCP(ip, port, s.cfg.DiscoveryTimeout)
			return open || refused
		})
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-found:
		return true
	case <-done:
		select {
		case <-found:
			return true
		default:
			return false
		}
	}
}

func (s *Scanner) reverseDNS(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DNSTimeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// scanPorts port-scans ip and returns whichever ports were found open —
// against every TCP port (1-65535) if deep is set, otherwise the curated
// ~280-port CommonPorts list a normal scan cycle uses.
func (s *Scanner) scanPorts(hostID int64, ip string, deep bool) map[int]bool {
	if deep {
		return s.scanPortRange(hostID, ip, allTCPPorts())
	}
	return s.scanPortRange(hostID, ip, CommonPorts)
}

func allTCPPorts() []int {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

// DeepScanHost port-scans every TCP port (1-65535) on ip, rather than the
// ~280-port CommonPorts list a normal scan cycle uses. It's a lot slower —
// meant to be triggered on demand for one host of particular interest (e.g.
// from the host modal), not run automatically across a whole subnet every
// cycle. Blocks until finished; use TriggerDeepScan to run it in the
// background.
func (s *Scanner) DeepScanHost(hostID int64, ip string) bool {
	return len(s.scanPortRange(hostID, ip, allTCPPorts())) > 0
}

// TriggerDeepScan starts a DeepScanHost run in the background for hostID/ip,
// unless one is already running for that host. Returns whether a new scan
// was actually started. Emits deep_scan_started/deep_scan_finished events
// so the UI can show progress and pick up newly-found ports as they land.
func (s *Scanner) TriggerDeepScan(hostID int64, ip string) bool {
	s.deepScanMu.Lock()
	if s.deepScanning[hostID] {
		s.deepScanMu.Unlock()
		return false
	}
	s.deepScanning[hostID] = true
	s.deepScanMu.Unlock()

	s.emit("deep_scan_started", fmt.Sprintf("Deep scan (all 65535 ports) started for %s — this can take a few minutes", ip), hostID)

	go func() {
		defer func() {
			s.deepScanMu.Lock()
			delete(s.deepScanning, hostID)
			s.deepScanMu.Unlock()
		}()
		s.DeepScanHost(hostID, ip)
		s.emit("deep_scan_finished", fmt.Sprintf("Deep scan finished for %s", ip), hostID)
	}()
	return true
}

// scanPortRange probes each of ports on ip, records whichever are open, and
// closes out any previously-open port this scan didn't find — then returns
// the set of ports found open.
func (s *Scanner) scanPortRange(hostID int64, ip string, ports []int) map[int]bool {
	sem := make(chan struct{}, s.cfg.PortConcurrency)
	var wg sync.WaitGroup
	open := make(map[int]bool)
	probed := make(map[int]bool, len(ports))
	var openMu sync.Mutex

	for _, port := range ports {
		probed[port] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.probeOnePort(hostID, ip, port) {
				openMu.Lock()
				open[port] = true
				openMu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	closed, err := s.st.SweepClosedPorts(hostID, probed, open)
	if err != nil {
		log.Printf("sweep closed ports: %v", err)
		return open
	}
	for _, port := range closed {
		s.emit("port_closed", fmt.Sprintf("Port %d/tcp on %s is no longer open", port, ip), hostID)
	}
	return open
}

// probeOnePort checks a single port on ip and records it if open, returning
// whether it was found open.
func (s *Scanner) probeOnePort(hostID int64, ip string, port int) bool {
	isOpen, _ := ProbeTCP(ip, port, s.cfg.PortTimeout)
	if !isOpen {
		return false
	}

	banner := GrabBanner(ip, port, s.cfg.PortTimeout)
	// No product/version: real version identification is nmap's -sV job:
	// the built-in prober only has a raw banner and a port-number guess.
	s.recordOpenPort(hostID, ip, port, serviceGuess(port), banner, "", "")
	return true
}

// recordOpenPort upserts an open port and, if it's newly seen, emits the
// new_port event and re-flags the host if it was previously acknowledged —
// shared by the built-in prober and the nmap scan path so both produce
// identical events for the same discovery. product/version come only from
// nmap's -sV output; the TCP path always passes them empty.
func (s *Scanner) recordOpenPort(hostID int64, ip string, port int, service, banner, product, version string) {
	isNew, err := s.st.UpsertPort(hostID, port, "tcp", service, banner, product, version)
	if err != nil {
		log.Printf("upsert port %s:%d: %v", ip, port, err)
		return
	}
	if isNew {
		desc := fmt.Sprintf("New open port %d/tcp on %s", port, ip)
		if service != "" {
			desc = fmt.Sprintf("New open port %d/tcp (%s) on %s", port, service, ip)
		}
		s.emit("new_port", desc, hostID)
		s.reflagIfAcknowledged(hostID, ip, port)
	}
}

// reflagIfAcknowledged un-exempts a previously-acknowledged host the moment
// a new port opens on it, since that's a material change from what was
// reviewed at ack time — and raises it back to a priority notification
// rather than letting it quietly stay acknowledged.
func (s *Scanner) reflagIfAcknowledged(hostID int64, ip string, port int) {
	wasAcked, err := s.st.ClearAcknowledgementIfSet(hostID)
	if err != nil {
		log.Printf("clear acknowledgement for host %d: %v", hostID, err)
		return
	}
	if wasAcked {
		s.emit("priority_reflag", fmt.Sprintf(
			"Port %d/tcp opened on %s — previously acknowledged, now re-flagged as priority", port, ip), hostID)
	}
}
