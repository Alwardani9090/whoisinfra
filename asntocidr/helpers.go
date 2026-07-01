package asntocidr

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func normalLizeASN(asn string) string {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	if !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}
	return asn
}
func readASNFromStdin() ([]string, error) {
	var asns []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			asns = append(asns, line)
		}
	}
	return asns, scanner.Err()
}
func parseFlags() (asn, server string, stdin bool, timeout time.Duration) {
	flag.StringVar(&asn, "asn", "", "ASN to Lookup (e.g. , AS15169 , 15169 )")
	flag.BoolVar(&stdin, "stdin", false, "Read ASN from STDIN(one per line)")
	flag.StringVar(&server, "server", defaultServer, "IRR WHOIS server")
	flag.DurationVar(&timeout, "timeout", defaultTimeout, "WHOIS timeout")
	flag.Parse()
	return
}
func collectASNs(asn string, stdin bool) []string {
	if stdin {
		list, err := readASNFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading ASNs from STDIN: %v\n", err)
			os.Exit(1)
		}
		return list
	}
	if asn != "" {
		return []string{asn}
	}
	fmt.Fprintln(os.Stderr, "Usage: asntocidr -asn AS15169")
	fmt.Fprintln(os.Stderr, "  or: echo AS15169 | asntocidr -stdin")
	flag.PrintDefaults()
	os.Exit(2)
	return nil
}
