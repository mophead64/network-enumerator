package discovery

import (
	"net"
)

// LocalSubnet describes a subnet this machine is directly attached to.
type LocalSubnet struct {
	CIDR  string
	Iface string
}

// LocalSubnets enumerates the IPv4 subnets this host is directly connected
// to, by inspecting its network interfaces. Loopback and link-local
// interfaces are skipped since scanning them is never useful.
func LocalSubnets() ([]LocalSubnet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []LocalSubnet
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			network := &net.IPNet{IP: ip4.Mask(ipNet.Mask), Mask: ipNet.Mask}
			cidr := network.String()
			key := cidr
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, LocalSubnet{CIDR: cidr, Iface: iface.Name})
		}
	}
	return out, nil
}
