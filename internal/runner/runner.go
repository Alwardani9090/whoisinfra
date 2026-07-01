package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Alwardani9090/whois/asntocidr"
	"github.com/Alwardani9090/whois/cidrtoips"
	"github.com/Alwardani9090/whois/internal/progress"
	"github.com/Alwardani9090/whois/whois"
)

type Options struct {
	Domain    string
	Timeout   time.Duration
	ExpandIPs bool
	Silent    bool
	Stderr    io.Writer
}

type Asset struct {
	SchemaVersion string              `json:"schema_version"`
	Domain        string              `json:"domain,omitempty"`
	Whois         map[string][]string `json:"whois,omitempty"`
	ASN           *ASNInfo            `json:"asn,omitempty"`
	CIDRs         []string            `json:"cidrs,omitempty"`
	IPs           []IPInfo            `json:"ips,omitempty"`
	Metadata      Metadata            `json:"metadata"`
}

type ASNInfo struct {
	Number      string `json:"number"`
	Name        string `json:"name,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
}

type IPInfo struct {
	Addr string `json:"addr"`
}

type Metadata struct {
	Tool         string    `json:"tool"`
	Source       string    `json:"source,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

func Run(ctx context.Context, opts Options) (*Asset, error) {
	if opts.Domain == "" {
		return nil, errors.New("whois: Domain is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	asset := &Asset{
		SchemaVersion: "1",
		Domain:        opts.Domain,
		Metadata: Metadata{
			Tool:         "whois",
			DiscoveredAt: time.Now().UTC(),
		},
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	progress.WriteToolProgress(opts.Stderr, 0, 2, "domain-whois")

	if info, err := whois.QueryDomainWhois(opts.Domain); err != nil {
		opts.warn("domain whois: %v", err)
	} else {
		asset.Whois = info
	}
	progress.WriteToolProgress(opts.Stderr, 1, 2, "resolve-ips")

	if err := ctx.Err(); err != nil {
		return asset, err
	}

	ips, err := net.LookupIP(opts.Domain)
	if err != nil {
		return asset, fmt.Errorf("resolve %s: %w", opts.Domain, err)
	}
	totalSteps := 2 + len(ips)
	progress.WriteToolProgress(opts.Stderr, 2, totalSteps, "asn-cidr")

	seenASN := map[string]bool{}
	for i, ip := range ips {
		if err := ctx.Err(); err != nil {
			return asset, err
		}
		ipStr := ip.String()
		asset.IPs = append(asset.IPs, IPInfo{Addr: ipStr})
		asn, asName, _, err := whois.LookupASN_Cymru(ipStr)
		if err != nil {
			opts.warn("asn lookup %s: %v", ipStr, err)
			continue
		}
		if seenASN[asn] {
			continue
		}
		seenASN[asn] = true

		if asset.ASN == nil {
			asset.ASN = &ASNInfo{Number: asn, Name: asName}
		}

		lookup := asntocidr.NewASNLookup(asn, "", timeout)
		cidrs, err := lookup.Query()
		if err != nil {
			opts.warn("cidr lookup %s: %v", asn, err)
			continue
		}
		asset.CIDRs = append(asset.CIDRs, cidrs...)

		if opts.ExpandIPs {
			for _, cidr := range cidrs {
				ipsList, err := cidrtoips.CIDRtoIPS(cidr)
				if err != nil {
					opts.warn("expand %s: %v", cidr, err)
					continue
				}
				for _, a := range ipsList {
					asset.IPs = append(asset.IPs, IPInfo{Addr: a})
				}
			}
		}
		progress.WriteToolProgress(opts.Stderr, 3+i, totalSteps, "asn-cidr")
	}
	return asset, nil
}

func (a *Asset) EncodeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(a)
}

func (o Options) warn(format string, args ...any) {
	if o.Silent || o.Stderr == nil {
		return
	}
	fmt.Fprintf(o.Stderr, "whois: "+format+"\n", args...)
}
