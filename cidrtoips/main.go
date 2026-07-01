package cidrtoips

import (
	"fmt"
	"net/netip"
)

func CIDRtoIPS(cidr string) ([]string, error) {
	var ips []string
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil,
			fmt.Errorf("invalid CDIR %q: %v", cidr, err)

	}
	addr := prefix.Addr()

	for prefix.Contains(addr) {
		ips = append(ips, addr.String())
		addr = addr.Next()
	}
	return ips, nil
}
