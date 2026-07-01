package whois

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

var Keys = []string{
	"Domain Name",
	"Registry Domain ID",
	"Registrar",
	"Creation Date",
	"Updated Date",
	"Registry Expiry Date",
	"Domain Status",
	"Registrar Abuse Contact Email",
	"Registrant Organization",
	"Admin Email",
	"Tech Email",
	"Name Server",
}

func PrintingWhoisData(whoisdata map[string][]string, keys []string) {
	for _, k := range keys {
		if vals, ok := whoisdata[k]; ok {
			if len(vals) > 1 {
				fmt.Printf(" %s:\n", k)
				sort.Strings(vals)
				for _, v := range vals {
					fmt.Printf("   - %s\n", v)
				}
			} else {
				fmt.Printf(" %s: %s\n", k, vals[0])
			}
		}
	}
}
func QueryDomainWhois(domain string) (map[string][]string, error) {
	whoisdata, err := queryDomainWhois(domain)
	if err != nil {
		return nil, err
	}

	return parsingWhoisData(whoisdata), nil
}
func queryDomainWhois(domain string) (string, error) {
	server := "whois.verisign-grs.com:43"
	conn, err := net.DialTimeout("tcp", server, 15*time.Second)
	if err != nil {
		return "",
			fmt.Errorf("Connection Faild : %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "=%s\r\n", domain)

	data, err := io.ReadAll(conn)
	if err != nil {
		return "",
			fmt.Errorf("Reading data Faild : %v", err)
	}

	data = []byte(string(data))

	return string(data), nil
}
func LookupASN_Cymru(ip string) (asn, asName, prefix string, err error) {
	asn, asName, prefix, err = lookupASN_Cymru(ip)
	if err != nil {
		return "", "", prefix, err
	}
	return
}

func lookupASN_Cymru(ip string) (asn, asName, prefix string, err error) {
	server := "whois.cymru.com:43"
	conn, err := net.DialTimeout("tcp", server, 10*time.Second)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	fmt.Fprintf(conn, " -v %s\n", ip)

	scanner := bufio.NewScanner(conn)
	if scanner.Scan() {
	}
	if scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			return "", "", "",
				fmt.Errorf("unexpected response: %s", line)
		}
		asn = strings.TrimSpace(fields[0])
		prefix = strings.TrimSpace(fields[2])
		asName = strings.TrimSpace(fields[6])
		return asn, asName, prefix, nil
	}
	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}
	return "", "", "", fmt.Errorf("no ASN found for IP %s", ip)
}
