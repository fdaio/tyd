package transport

import (
	"net"
	"sort"
	"strings"
)

// ExpandCandidates builds dial targets for a data-plane listener.
// listenAddr is the actual bound address (may be 0.0.0.0:port).
// advertise, when set, is tried first (operator override / public hostname).
func ExpandCandidates(listenAddr, advertise string) []string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		if listenAddr != "" {
			return []string{listenAddr}
		}
		return nil
	}

	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || h == "0.0.0.0" || h == "::" {
			return
		}
		addr := net.JoinHostPort(h, port)
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	add(advertise)
	if host != "" && host != "0.0.0.0" && host != "::" {
		add(host)
	}

	ifaces, err := net.InterfaceAddrs()
	if err == nil {
		var extras []string
		for _, ia := range ifaces {
			ipnet, ok := ia.(*net.IPNet)
			if !ok || ipnet.IP == nil {
				continue
			}
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				extras = append(extras, v4.String())
				continue
			}
			// skip IPv6 for Phase 1 dial simplicity (still publish if needed later)
		}
		sort.Strings(extras)
		for _, h := range extras {
			add(h)
		}
	}

	// Same-host / CI: always offer loopback last.
	add("127.0.0.1")
	return out
}
