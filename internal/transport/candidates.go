package transport

import (
	"net"
	"sort"
	"strings"
)

// ExpandCandidates builds dial targets for a data-plane listener.
// listenAddr is the actual bound address (may be 0.0.0.0:port).
// advertise, when set to a non-loopback host, is tried first (operator override).
// Loopback is always last (same-host / CI only).
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

	if adv := strings.TrimSpace(advertise); adv != "" && !isLoopbackHost(adv) {
		add(adv)
	}
	if host != "" && host != "0.0.0.0" && host != "::" && !isLoopbackHost(host) {
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
			}
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

// PreferNonLoopback reorders dial targets so loopback addresses are tried last.
func PreferNonLoopback(addrs []string) []string {
	seen := map[string]struct{}{}
	var primary, loop []string
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			host = a
		}
		if isLoopbackHost(host) {
			loop = append(loop, a)
			continue
		}
		primary = append(primary, a)
	}
	return append(primary, loop...)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
