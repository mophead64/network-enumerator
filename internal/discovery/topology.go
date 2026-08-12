package discovery

import (
	"fmt"
	"net"
	"regexp"
	"sort"

	"network-enumerator/internal/model"
)

// NodeKind identifies what a TopologyEdge's endpoint actually is: the app's
// own host (the trace origin), a subnet already known to the inventory, or
// an inferred "transit" bucket — a hop that answered from an address
// outside every known subnet — grouped so the Map view/draw.io export can
// show it as a single "undocumented" box rather than one dangling node per
// hop. A hop that never answered at all carries no such information and is
// disregarded entirely rather than represented as a node — see
// classifySegment.
type NodeKind string

const (
	NodeOrigin  NodeKind = "origin"
	NodeSubnet  NodeKind = "subnet"
	NodeTransit NodeKind = "transit"
)

// NodeRef identifies one endpoint of a TopologyEdge. SubnetID is set only
// for NodeSubnet; TransitKey only for NodeTransit (see transitKey).
type NodeRef struct {
	Kind       NodeKind `json:"kind"`
	SubnetID   int64    `json:"subnetId,omitempty"`
	TransitKey string   `json:"transitKey,omitempty"`
}

func (n NodeRef) key() string {
	switch n.Kind {
	case NodeSubnet:
		return fmt.Sprintf("subnet:%d", n.SubnetID)
	case NodeTransit:
		return "transit:" + n.TransitKey
	default:
		return "origin"
	}
}

// TopologyEdge is one link between two nodes in the merged topology graph —
// a subnet crossing found by a traceroute hop stepping from one classified
// segment (see classifySegment) into another. ViaIP is the router/hop
// address the crossing happened at; empty when Responded is false (the hop
// that would identify it never replied).
type TopologyEdge struct {
	A         NodeRef `json:"a"`
	B         NodeRef `json:"b"`
	ViaIP     string  `json:"viaIp,omitempty"`
	HopIndex  int     `json:"hopIndex"`
	Responded bool    `json:"responded"`
	RTTMs     float64 `json:"rttMs,omitempty"`
	LossPct   float64 `json:"lossPct,omitempty"`
	Method    string  `json:"method,omitempty"`
}

// TransitBucket is one "undocumented" grouping referenced by a TopologyEdge
// with Kind NodeTransit — a cluster of hop IPs sharing an inferred /24 that
// don't fall inside any known subnet.
type TransitBucket struct {
	Key  string   `json:"key"`
	CIDR string   `json:"cidr,omitempty"`
	IPs  []string `json:"ips,omitempty"`
}

type TopologyGraph struct {
	Edges   []TopologyEdge  `json:"edges"`
	Transit []TransitBucket `json:"transit"`
}

// segment is one hop classified against known subnets — the unit
// BuildTopologyGraph collapses consecutive duplicates of before turning a
// single subnet's traced path into a chain of edges.
type segment struct {
	node NodeRef
	hop  model.TopologyHop // the hop that first entered this segment
}

// classifySegment maps one responded hop to the node it represents: a known
// subnet if the hop's IP falls inside one of subnetNets, otherwise a
// transit bucket keyed by the hop's /24 (so nearby hop IPs on the same
// unlisted segment collapse into one box). Callers only ever pass a hop
// that actually replied — see BuildTopologyGraph, which disregards
// unresponsive hops before they ever reach here: a hop that never answered
// carries no information to build a node from (not "an unknown router",
// just "no signal"), so rather than clutter the graph with a placeholder
// for it, it's simply skipped — any two real segments either side of a
// stretch of silence connect directly to each other.
func classifySegment(subnetNets map[int64]*net.IPNet, hop model.TopologyHop) (NodeRef, *TransitBucket) {
	ip := net.ParseIP(hop.IP)
	if ip != nil {
		for sid, ipnet := range subnetNets {
			if ipnet.Contains(ip) {
				return NodeRef{Kind: NodeSubnet, SubnetID: sid}, nil
			}
		}
	}
	cidr := hop.IP + "/32"
	key := hop.IP
	if ip4 := ip.To4(); ip4 != nil {
		masked := ip4.Mask(net.CIDRMask(24, 32))
		cidr = masked.String() + "/24"
		key = cidr
	}
	return NodeRef{Kind: NodeTransit, TransitKey: key}, &TransitBucket{Key: key, CIDR: cidr, IPs: []string{hop.IP}}
}

// BuildTopologyGraph turns every subnet's raw traced hop list into a merged
// subnet-to-subnet (and subnet-to-transit) link graph: for each subnet's
// path, consecutive hops are classified (classifySegment) and collapsed
// into a chain of distinct segments from the trace origin to the target
// subnet, then adjacent segments become edges. Edges observed identically
// (same endpoints and crossing IP) across more than one subnet's trace are
// deduplicated, since two traces sharing an upstream hop is expected and
// shouldn't draw the same router link twice.
func BuildTopologyGraph(subnets []model.Subnet, hops []model.TopologyHop) TopologyGraph {
	subnetNets := make(map[int64]*net.IPNet, len(subnets))
	for _, sn := range subnets {
		if _, ipnet, err := net.ParseCIDR(sn.CIDR); err == nil {
			subnetNets[sn.ID] = ipnet
		}
	}

	byTarget := make(map[int64][]model.TopologyHop)
	for _, h := range hops {
		byTarget[h.SubnetID] = append(byTarget[h.SubnetID], h)
	}

	edgeSeen := make(map[string]bool)
	edges := []TopologyEdge{}
	transitBuckets := make(map[string]*TransitBucket)

	for targetSubnetID, targetHops := range byTarget {
		sort.Slice(targetHops, func(i, j int) bool { return targetHops[i].HopIndex < targetHops[j].HopIndex })

		segments := []segment{{node: NodeRef{Kind: NodeOrigin}}}
		for _, hop := range targetHops {
			if !hop.Responded || hop.IP == "" {
				continue // disregarded — see classifySegment's doc comment
			}
			node, bucket := classifySegment(subnetNets, hop)
			if bucket != nil {
				existing := transitBuckets[bucket.Key]
				if existing == nil {
					transitBuckets[bucket.Key] = bucket
				} else if len(bucket.IPs) > 0 && !containsStr(existing.IPs, bucket.IPs[0]) {
					existing.IPs = append(existing.IPs, bucket.IPs[0])
				}
			}
			if segments[len(segments)-1].node.key() == node.key() {
				continue // still inside the same segment — collapse, keep the first hop that entered it
			}
			segments = append(segments, segment{node: node, hop: hop})
		}

		// Guarantee the path ends at the subnet the trace was actually run
		// for — the last responded hop should already land there in
		// practice, but a firewall dropping the final probe (a common,
		// expected case) would otherwise leave the path short. Appending it
		// unconditionally when missing keeps every subnet represented in
		// the graph even when its own last hop didn't respond; Responded on
		// that edge reflects whether this was actually observed or merely
		// inferred.
		targetNode := NodeRef{Kind: NodeSubnet, SubnetID: targetSubnetID}
		last := segments[len(segments)-1]
		if last.node.key() != targetNode.key() {
			segments = append(segments, segment{
				node: targetNode,
				hop: model.TopologyHop{
					HopIndex:  last.hop.HopIndex + 1,
					Responded: false, // inferred, not an actually-observed hop landing in this subnet
					Method:    last.hop.Method,
				},
			})
		}

		for i := 1; i < len(segments); i++ {
			a, b := segments[i-1].node, segments[i].node
			hop := segments[i].hop
			edgeKey := a.key() + "|" + b.key() + "|" + hop.IP
			if a.key() > b.key() {
				edgeKey = b.key() + "|" + a.key() + "|" + hop.IP
			}
			if edgeSeen[edgeKey] {
				continue
			}
			edgeSeen[edgeKey] = true
			edges = append(edges, TopologyEdge{
				A: a, B: b, ViaIP: hop.IP, HopIndex: hop.HopIndex, Responded: hop.Responded,
				RTTMs: hop.RTTMs, LossPct: hop.LossPct, Method: hop.Method,
			})
		}
	}

	buckets := make([]TransitBucket, 0, len(transitBuckets))
	for _, b := range transitBuckets {
		buckets = append(buckets, *b)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Key < buckets[j].Key })
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].A.key() != edges[j].A.key() {
			return edges[i].A.key() < edges[j].A.key()
		}
		return edges[i].B.key() < edges[j].B.key()
	})

	return TopologyGraph{Edges: edges, Transit: buckets}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// gatewayNameRe matches a hostname that strongly suggests a router/gateway
// device — the same signal the draw.io export's inferHostKind heuristic
// uses client-side (see web/static/app.js), ported here so the topology
// scan's target-host choice and the export's icon choice agree.
var gatewayNameRe = regexp.MustCompile(`(?i)(^|[-_.])(rtr|router|gw|gateway|fw|firewall)([-_.]|$)`)

// isLikelyGateway reports whether h looks like a subnet's router: address
// ending in .1, or a name matching gatewayNameRe.
func isLikelyGateway(h model.Host) bool {
	if ip := net.ParseIP(h.IP).To4(); ip != nil && ip[3] == 1 {
		return true
	}
	return gatewayNameRe.MatchString(h.Hostname)
}

// ipLess orders two dotted-quad IPv4 addresses numerically (10.0.0.2 before
// 10.0.0.10) rather than lexically, falling back to a plain string compare
// for anything that doesn't parse as IPv4.
func ipLess(a, b string) bool {
	ai, bi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	for i := range ai {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return false
}

// pickTopologyTarget chooses which host in subnetID a topology scan should
// traceroute to: the first live host that looks like a gateway (see
// isLikelyGateway), or failing that the numerically lowest live IP — a
// stable, deterministic choice re-run after re-run so the same subnet keeps
// tracing to the same target rather than a route seemingly changing hop by
// hop just because a different host got picked. Returns "" when the subnet
// has no host currently marked up.
func pickTopologyTarget(subnetID int64, hosts []model.Host) string {
	var candidates []model.Host
	for _, h := range hosts {
		if h.SubnetID == subnetID && h.Status == "up" {
			candidates = append(candidates, h)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool { return ipLess(candidates[i].IP, candidates[j].IP) })
	for _, h := range candidates {
		if isLikelyGateway(h) {
			return h.IP
		}
	}
	return candidates[0].IP
}
