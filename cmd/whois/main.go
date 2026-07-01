package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Alwardani9090/whois/internal/runner"
	"github.com/Alwardani9090/whois/whois"
)

func main() {
	var (
		domain    = flag.String("d", "", "target domain (or pass via -i/-)")
		input     = flag.String("i", "", "input file with one domain per line (use '-' for stdin)")
		output    = flag.String("o", "", "output file (default: stdout)")
		timeout   = flag.Duration("timeout", 20*time.Second, "per-lookup timeout")
		jsonMode  = flag.Bool("json", false, "emit NDJSON (Asset schema) instead of text")
		expandIPs = flag.Bool("expand-ips", false, "list every IP inside each CIDR (large output)")
		silent    = flag.Bool("silent", false, "suppress progress messages on stderr")
	)
	flag.Parse()

	targets, err := resolveTargets(*domain, *input)
	if err != nil {
		fatal(err)
	}
	if len(targets) == 0 {
		fatal(fmt.Errorf("no target: pass -d, -i <file>, or pipe on stdin"))
	}

	out := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fatal(fmt.Errorf("create %s: %w", *output, err))
		}
		defer f.Close()
		out = f
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	for _, t := range targets {
		asset, err := runner.Run(ctx, runner.Options{
			Domain:    t,
			Timeout:   *timeout,
			ExpandIPs: *expandIPs,
			Silent:    *silent,
			Stderr:    os.Stderr,
		})
		if err != nil && asset == nil {
			fmt.Fprintf(os.Stderr, "whois %s: %v\n", t, err)
			continue
		}
		if *jsonMode {
			if err := asset.EncodeJSON(out); err != nil {
				fatal(err)
			}
			continue
		}
		writeText(out, asset)
	}
}

func resolveTargets(domain, input string) ([]string, error) {
	if domain != "" {
		return []string{strings.TrimSpace(domain)}, nil
	}
	if input != "" {
		r, closer, err := openInput(input)
		if err != nil {
			return nil, err
		}
		defer closer()
		return readLines(r)
	}
	if stdinIsPiped() {
		return readLines(os.Stdin)
	}
	return nil, nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func readLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

func stdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func writeText(w io.Writer, a *runner.Asset) {
	fmt.Fprintf(w, "== %s ==\n", a.Domain)
	if len(a.Whois) > 0 {
		writeWhoisFields(w, a.Whois, whois.Keys)
	}
	if a.ASN != nil {
		fmt.Fprintf(w, "  ASN:   %s", a.ASN.Number)
		if a.ASN.Name != "" {
			fmt.Fprintf(w, " (%s)", a.ASN.Name)
		}
		fmt.Fprintln(w)
	}
	cidrs := append([]string(nil), a.CIDRs...)
	sort.Strings(cidrs)
	for _, c := range cidrs {
		fmt.Fprintf(w, "  CIDR:  %s\n", c)
	}
	for _, ip := range a.IPs {
		fmt.Fprintf(w, "  IP:    %s\n", ip.Addr)
	}
}

func writeWhoisFields(w io.Writer, data map[string][]string, keys []string) {
	for _, k := range keys {
		vals, ok := data[k]
		if !ok {
			continue
		}
		if len(vals) > 1 {
			fmt.Fprintf(w, " %s:\n", k)
			sorted := append([]string(nil), vals...)
			sort.Strings(sorted)
			for _, v := range sorted {
				fmt.Fprintf(w, "   - %s\n", v)
			}
			continue
		}
		fmt.Fprintf(w, " %s: %s\n", k, vals[0])
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "whois:", err)
	os.Exit(1)
}
