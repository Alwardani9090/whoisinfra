package asntocidr

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	defaultServer  = "whois.radb.net:43"
	defaultTimeout = 20 * time.Second
)

type ASNLookup struct {
	asn     string
	server  string
	timeout time.Duration
}

func NewASNLookup(asn, server string, timeout time.Duration) *ASNLookup {
	asn = normalLizeASN(asn)
	if server == "" {
		server = defaultServer
	}
	return &ASNLookup{
		asn:     asn,
		server:  server,
		timeout: timeout,
	}
}
func (l *ASNLookup) Query() ([]string, error) {
	resp, err := l.query()
	if err != nil {
		return nil, err
	}
	return parseCIDRs(resp), nil
}
func (l *ASNLookup) query() (string, error) {
	server := l.server
	conn, err := net.DialTimeout("tcp", server, l.timeout)
	if err != nil {
		return " ",
			fmt.Errorf("connection failed :  %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(l.timeout))
	if _, err := fmt.Fprintf(conn, "-i origin  %s\r\n", l.asn); err != nil {
		return "", err
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return "",
			fmt.Errorf("failed to read response :  %v", err)
	}

	return string(data), nil
}
func parseCIDRs(whoisResp string) []string {
	var cidrs []string
	for _, line := range strings.Split(whoisResp, "\n") {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "route:") {
			continue
		}

		cidr := strings.TrimPrefix(line, "route:")

		cidr = strings.TrimSpace(cidr)

		cidrs = append(cidrs, cidr)
	}
	return cidrs
}
