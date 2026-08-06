package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
)

// MaxHostsPerSubnet caps how many addresses a single subnet scan will
// expand to. Field environments occasionally have a fat-fingered /8 added
// by hand (or an auto-discovered interface subnet that's much bigger than
// what's actually in use, e.g. Docker's default /16 bridge network); without
// a cap that turns into a scan that never finishes. Overridable via the
// MAX_HOSTS_PER_SUBNET env var for cases where scanning a genuinely large
// range is intended.
var MaxHostsPerSubnet = 4096

// ExpandIPv4 returns every usable host address in cidr (network and
// broadcast addresses excluded for subnets smaller than /31), capped at
// MaxHostsPerSubnet.
func ExpandIPv4(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only ipv4 is supported: %q", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits > 32 {
		hostBits = 32
	}
	total := uint64(1) << uint(hostBits)

	start := binary.BigEndian.Uint32(ipNet.IP.To4())
	skipFirstLast := hostBits >= 2 // /31 and /32 have no distinct network/broadcast

	var out []net.IP
	for i := uint64(0); i < total && uint64(len(out)) < uint64(MaxHostsPerSubnet); i++ {
		if skipFirstLast && (i == 0 || i == total-1) {
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], start+uint32(i))
		addr := net.IPv4(b[0], b[1], b[2], b[3])
		out = append(out, addr)
	}
	return out, nil
}
