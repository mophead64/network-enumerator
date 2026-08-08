package discovery

// DiscoveryPorts is a small set of near-universally-listening ports used
// during the host-discovery phase, where the only question is "is anything
// here at all". Keeping this list short keeps discovery fast even on large
// subnets.
var DiscoveryPorts = []int{22, 80, 443, 445, 139, 135, 3389, 21, 23, 53, 25, 8080, 8443, 631, 5000, 111}

// CommonPorts is the port set used for the full per-host scan once a host
// has been confirmed alive. It favors breadth over the exhaustive 1-65535
// range to keep scan time reasonable on constrained/unstable networks.
var CommonPorts = []int{
	7, 9, 13, 20, 21, 22, 23, 25, 26, 37, 49, 53, 67, 68, 69, 79,
	80, 81, 82, 88, 106, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 144,
	161, 162, 179, 199, 389, 427, 443, 444, 445, 464, 465, 500, 512, 513, 514, 515,
	543, 544, 548, 554, 587, 593, 623, 631, 636, 646, 787, 800, 801, 808, 873, 902,
	903, 989, 990, 992, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1099, 1194, 1234, 1433,
	1434, 1521, 1527, 1701, 1723, 1755, 1900, 2000, 2001, 2049, 2055, 2082, 2083, 2086, 2087, 2095,
	2096, 2181, 2222, 2375, 2376, 2379, 2380, 2483, 2484, 3000, 3001, 3128, 3260, 3268, 3269, 3306,
	3389, 3690, 3691, 4000, 4040, 4190, 4243, 4369, 4443, 4444, 4500, 4567, 4664, 4848, 4899, 5000,
	5001, 5040, 5060, 5061, 5222, 5269, 5353, 5355, 5357, 5432, 5433, 5555, 5601, 5631, 5672, 5900,
	5901, 5902, 5903, 5984, 5985, 5986, 6000, 6001, 6379, 6443, 6600, 6666, 6667, 6881, 7000, 7001,
	7070, 7077, 7080, 7100, 7180, 7182, 7183, 7199, 7233, 7236, 7443, 7474, 7547, 7657, 7777, 7778,
	8000, 8001, 8006, 8008, 8009, 8010, 8020, 8025, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8086,
	8087, 8088, 8089, 8090, 8091, 8096, 8112, 8123, 8140, 8161, 8181, 8182, 8200, 8222, 8291, 8333,
	8400, 8443, 8444, 8500, 8530, 8531, 8545, 8728, 8729, 8834, 8880, 8883, 8888, 8889, 8983, 9000,
	9001, 9042, 9043, 9060, 9080, 9090, 9091, 9092, 9100, 9160, 9200, 9300, 9418, 9443, 9500, 9502,
	9600, 9990, 9995, 9999, 10000, 10001, 10250, 10255, 10257, 10259, 11211, 11434, 12345, 15672, 16992, 16993,
	17000, 17185, 18080, 18081, 19132, 20000, 20547, 21025, 25565, 27015, 27017, 27018, 28015, 32400, 32764, 32768,
	44818, 47808, 49152, 49153, 49154, 49155, 50000, 50070, 54321, 55443, 61616,
}

// wellKnownServices maps a handful of common ports to a human-readable
// service label, used when a banner grab doesn't yield anything better.
var wellKnownServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap", 443: "https",
	445: "microsoft-ds", 465: "smtps", 514: "syslog", 515: "printer",
	548: "afp", 554: "rtsp", 587: "submission", 593: "http-rpc-epmap",
	631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
	1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper",
	2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3268: "ldap-gc",
	3306: "mysql", 3389: "rdp", 3690: "svn", 5000: "http-alt", 5432: "postgresql",
	5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb",
	5985: "winrm", 5986: "winrm-ssl", 6379: "redis", 6443: "kubernetes-api",
	6667: "irc", 7001: "weblogic", 8000: "http-alt", 8006: "proxmox",
	8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8086: "influxdb",
	8443: "https-alt", 8888: "http-alt", 8983: "solr", 9000: "http-alt",
	9042: "cassandra", 9092: "kafka", 9100: "printer-jetdirect", 9200: "elasticsearch",
	9300: "elasticsearch-transport", 10250: "kubelet", 11211: "memcached",
	15672: "rabbitmq-mgmt", 27017: "mongodb", 32400: "plex",
	49: "tacacs", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 123: "ntp",
	137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 162: "snmptrap",
	464: "kpasswd", 500: "isakmp", 623: "ipmi", 873: "rsync", 1194: "openvpn",
	1527: "derby", 1701: "l2tp", 2055: "netflow", 2379: "etcd-client",
	2380: "etcd-peer", 3269: "ldap-gc-ssl", 4190: "sieve", 4243: "docker-alt",
	4500: "ipsec-nat-t", 5001: "https-alt", 5060: "sip", 5061: "sips",
	5902: "vnc", 5903: "vnc", 8001: "kubernetes-api", 8088: "http-alt",
	8291: "mikrotik-winbox", 8728: "mikrotik-api", 8729: "mikrotik-api-ssl",
	9090: "prometheus", 9443: "https-alt", 9995: "netflow", 10000: "webmin",
	10255: "kubelet-readonly", 10257: "kube-controller-manager",
	10259: "kube-scheduler", 27018: "mongodb", 50000: "db2",
}

func serviceGuess(port int) string {
	if s, ok := wellKnownServices[port]; ok {
		return s
	}
	return ""
}
