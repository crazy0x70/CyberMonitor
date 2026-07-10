package netguard

import (
	"net"
	"net/netip"
)

func IsAllowedPublicIP(ip net.IP) bool {
	addr, ok := AddrFromIP(ip)
	return ok && addr.IsGlobalUnicast() && IsAllowedPublicAddr(addr)
}

func AddrFromIP(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	if addr.Is4In6() {
		addr = netip.AddrFrom4([4]byte(addr.As4()))
	}
	return addr, true
}

func IsAllowedPublicAddr(addr netip.Addr) bool {
	for _, prefix := range blockedSpecialUsePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

var blockedSpecialUsePrefixes = mustParsePrefixes([]string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"::ffff:0:0/96",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
})

func mustParsePrefixes(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
