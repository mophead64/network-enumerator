package discovery

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// NmapPath reports the path to the nmap binary if it's on PATH, and whether
// it was found at all — callers use the bool to decide whether nmap-based
// scanning is available on this host.
func NmapPath() (string, bool) {
	p, err := exec.LookPath("nmap")
	return p, err == nil
}

// NmapHost is one <host> entry parsed out of nmap's XML output.
type NmapHost struct {
	IP       string
	MAC      string
	Vendor   string
	Hostname string
	Ports    []NmapPort
}

type NmapPort struct {
	Port    int
	Service string
	Banner  string
	Product string // e.g. "OpenSSH" — only populated by -sV version detection
	Version string // e.g. "7.4"     — only populated by -sV version detection
}

// RunNmap runs nmap against exactly targets (one or more IPs — not a CIDR)
// for the given ports and returns every host it found up. targets is meant
// to already be a confirmed-alive list from the built-in prober's fast
// TCP/ICMP probe: -Pn tells nmap to skip its own host-discovery sweep and
// treat every target as up, since nmap's own discovery (especially combined
// with -sV below) is markedly slower than the built-in prober's — running it
// across a whole subnet's worth of mostly-empty address space was the
// biggest cost in an nmap-based scan cycle. Uses a TCP connect scan (-sT),
// the only scan type that works without CAP_NET_RAW/root — the same
// privilege level the built-in TCP prober already requires, so this works in
// exactly the same unprivileged deployments. -sV additionally probes each
// open port to identify the service's product/version (used by risk rules to
// flag outdated versions, not just risky ports) — it costs real scan time
// per open port, which is why hostTimeout exists: it bounds how long nmap
// will spend on any single host in total, so one host with many open ports
// can't stall an entire subnet's scan cycle on an unstable network.
//
// versionIntensity sets -sV's --version-intensity (0-9, nmap's own default
// is 7); pass 0 to omit the flag and use that default. Measured against a
// real host with several open, non-trivially-identified local services
// (macOS's AirPlay/RTSP receiver, CUPS, a couple of bare Go HTTP servers):
// intensity 3 identified every one of them exactly as well as the default
// 7 did — same product/version — in a fifth of the time (34s vs 161s). The
// extra time at higher intensities went entirely into extra low-probability
// probes that produced unrecognized-service fingerprint dumps this code
// doesn't even parse, not into better matches. Regular scan cycles pass a
// low intensity to stay fast; deep scans (already understood by users as
// slow but thorough) pass 0 for nmap's fuller default.
func RunNmap(ctx context.Context, path string, targets []string, ports []int, hostTimeout time.Duration, versionIntensity int) ([]NmapHost, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	args := []string{
		"-sT", "-sV", "-Pn", "-T4",
		// nmap's --host-timeout wants a plain "<number><unit>" like "90s" —
		// time.Duration's own String() produces compound forms ("5m0s",
		// "1m30s") that nmap rejects outright with "Bogus --host-timeout
		// argument specified", silently failing every nmap-based scan. Total
		// whole seconds sidesteps that entirely.
		"--host-timeout", fmt.Sprintf("%ds", int(hostTimeout.Seconds())),
		"-p", portsArg(ports),
		"-oX", "-",
	}
	if versionIntensity > 0 {
		args = append(args, "--version-intensity", strconv.Itoa(versionIntensity))
	}
	args = append(args, targets...)
	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var run nmapXMLRun
	if err := xml.Unmarshal(stdout.Bytes(), &run); err != nil {
		return nil, fmt.Errorf("parse nmap output: %w", err)
	}

	hosts := make([]NmapHost, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		var nh NmapHost
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4":
				nh.IP = a.Addr
			case "mac":
				nh.MAC = a.Addr
				nh.Vendor = a.Vendor
			}
		}
		if nh.IP == "" {
			continue // shouldn't happen for an IPv4 scan, but nothing to record without an address
		}
		if len(h.Hostnames.Hostname) > 0 {
			nh.Hostname = h.Hostnames.Hostname[0].Name
		}
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			nh.Ports = append(nh.Ports, NmapPort{
				Port:    p.PortID,
				Service: p.Service.Name,
				Product: p.Service.Product,
				Version: p.Service.Version,
			})
		}
		hosts = append(hosts, nh)
	}
	return hosts, nil
}

// portsArg renders ports as nmap's -p argument: the compact "1-65535" form
// for the full TCP range (matches allTCPPorts()), otherwise a comma list.
func portsArg(ports []int) string {
	if len(ports) == 65535 {
		return "1-65535"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

type nmapXMLRun struct {
	Hosts []nmapXMLHost `xml:"host"`
}

type nmapXMLHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Port []struct {
			PortID int `xml:"portid,attr"`
			State  struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
}
