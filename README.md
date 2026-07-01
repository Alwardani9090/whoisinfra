# whois

A fast, dependency-free CLI recon tool written in Go that chains **domain WHOIS → DNS resolution → ASN lookup → CIDR discovery** into a single command, and can emit clean, structured JSON for pipelines.

[![CI](https://github.com/Alwardani9090/whois/actions/workflows/ci.yml/badge.svg)](https://github.com/Alwardani9090/whois/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Alwardani9090/whois)](https://goreportcard.com/report/github.com/Alwardani9090/whois)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.22-00ADD8?logo=go)](go.mod)

---

## Why this tool?

Recon on a target domain usually means running several separate tools by hand: `whois` for the domain, `dig`/`nslookup` to resolve it, another `whois` query against a routing registry for the ASN, and yet another for the CIDR blocks that ASN owns. **`whois` does all of that in one pass**, for one domain or a whole list, and gives you the result as human-readable text or as newline-delimited JSON you can feed straight into `jq`, a database, or the next tool in your pipeline.

```
domain  →  WHOIS registry record  →  resolved IPs  →  ASN (via Team Cymru)  →  CIDR ranges (via IRR/RADb)
```

## Features

- 🔎 **Domain WHOIS** — registrar, creation/expiry dates, status, name servers, abuse contact, and more
- 🌐 **DNS resolution** — resolves the domain to its IPv4/IPv6 addresses
- 🛰 **ASN lookup** — maps each IP to its Autonomous System via the Team Cymru WHOIS service
- 📦 **CIDR discovery** — pulls the announced route blocks for that ASN from an IRR WHOIS server (RADb by default)
- 🧩 **CIDR expansion** *(optional)* — expand any discovered CIDR into its individual IP addresses
- 📄 **Two output modes** — readable text for humans, or NDJSON for machines/pipelines
- 📚 **Batch mode** — run against a single domain, a file of domains, or a piped stdin list
- 🪶 **Zero third-party dependencies** — pure Go standard library, nothing to `go get`

## Installation

### Using `go install`

```bash
go install github.com/Alwardani9090/whois/cmd/whois@latest
```

### From source

```bash
git clone https://github.com/Alwardani9090/whois.git
cd whois
go build -o whois ./cmd/whois
```

Requires **Go 1.22+**.

## Usage

```
whois -d <domain> [flags]
whois -i <file>            # one domain per line
cat domains.txt | whois    # read domains from stdin
```

### Flags

| Flag          | Description                                                  | Default |
|---------------|----------------------------------------------------------------|---------|
| `-d`          | Target domain                                                  | —       |
| `-i`          | Input file with one domain per line (`-` for stdin)             | —       |
| `-o`          | Output file (defaults to stdout)                                | stdout  |
| `-timeout`    | Per-lookup network timeout                                      | `20s`   |
| `-json`       | Emit NDJSON (one JSON object per domain) instead of text        | `false` |
| `-expand-ips` | Also list every individual IP inside each discovered CIDR (can be a **lot** of output) | `false` |
| `-silent`     | Suppress progress output on stderr                               | `false` |

### Examples

**Single domain, human-readable output:**

```bash
whois -d example.com
```

```
== example.com ==
 Domain Name: EXAMPLE.COM
 Registrar: RESERVED-Internet Assigned Numbers Authority
 Creation Date: 1995-08-14T04:00:00Z
 Registry Expiry Date: 2026-08-13T04:00:00Z
 Name Server:
   - A.IANA-SERVERS.NET
   - B.IANA-SERVERS.NET
  ASN:   AS15133 (EDGECAST)
  CIDR:  93.184.216.0/24
  IP:    93.184.216.34
```

**Batch mode from a file, output as NDJSON:**

```bash
whois -i domains.txt -json -o results.ndjson
```

**Pipe a list of domains in, expand CIDRs to individual IPs, and filter with `jq`:**

```bash
cat domains.txt | whois -json -expand-ips | jq -c '{domain, asn: .asn.number, ips: (.ips | length)}'
```

### JSON schema

Each line of `-json` output is a self-contained object:

```json
{
  "schema_version": "1",
  "domain": "example.com",
  "whois": { "Domain Name": ["EXAMPLE.COM"], "...": ["..."] },
  "asn": { "number": "AS15133", "name": "EDGECAST" },
  "cidrs": ["93.184.216.0/24"],
  "ips": [{ "addr": "93.184.216.34" }],
  "metadata": {
    "tool": "whois",
    "discovered_at": "2026-07-01T12:00:00Z"
  }
}
```

## Project structure

```
.
├── cmd/whois/          # CLI entry point (flag parsing, I/O, output formatting)
├── internal/runner/     # Orchestrates the whois → DNS → ASN → CIDR pipeline
├── internal/progress/   # Minimal, dependency-free progress reporting
├── whois/                # Domain WHOIS + ASN (Team Cymru) queries
├── asntocidr/            # ASN → CIDR lookups against an IRR/RADb WHOIS server
└── cidrtoips/             # CIDR → individual IP expansion
```

Each subpackage also works as a standalone library, so you can import just the piece you need (e.g. only `asntocidr` if you're only after CIDR blocks).

## How it works

1. **`whois`** opens a raw TCP connection to `whois.verisign-grs.com:43` to fetch the domain's registry record and parses it into a `map[string][]string`.
2. The domain is resolved to its IP addresses with the standard library's `net.LookupIP`.
3. For each unique IP, **`whois`** queries **`whois.cymru.com:43`** to resolve the owning ASN.
4. **`asntocidr`** queries an IRR WHOIS server (RADb by default, `-i origin` style query) to list the CIDR blocks announced by that ASN.
5. *(optional)* **`cidrtoips`** expands each CIDR into every individual address it contains.

All of this is coordinated by `internal/runner`, which also builds the structured `Asset` used for JSON output.

## Contributing

Issues and pull requests are welcome. If you're adding a feature, please keep the zero-dependency philosophy — this project intentionally sticks to the Go standard library.

## Disclaimer

This tool performs WHOIS/ASN/CIDR lookups against public registries. Only use it against domains and infrastructure you own or are authorized to assess. The author is not responsible for misuse.

## License

[MIT](LICENSE)
