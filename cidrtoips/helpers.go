package cidrtoips

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

func parseFlags() (cidr string, stdin bool) {
	flag.StringVar(&cidr, "cidr", "", "CIDR to lookup IPs for")
	flag.BoolVar(&stdin, "stdin", false, "Read IPs from STDIN(one per line)")
	flag.Parse()
	return
}
func CollectCidrs(cidr string, stdin bool) []string {
	if stdin {
		list, err := readCIDRFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CIDRs from STDIN: %v\n", err)
			os.Exit(1)
		}
		return list

	}
	if cidr != "" {
		return []string{cidr}
	}
	fmt.Fprintln(os.Stderr, "Reads CIDRs Ranges and outputs individaul IP addresses ")
	fmt.Fprintln(os.Stderr, "   or: cat cidrs.txt | cidrtoips ")
	flag.PrintDefaults()
	os.Exit(2)
	return nil

}
func readCIDRFromStdin() ([]string, error) {
	var cidrs []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cidrs = append(cidrs, line)
		}
	}
	return cidrs, scanner.Err()
}
