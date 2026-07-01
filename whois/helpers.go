package whois

import (
	"strings"
)

func parsingWhoisData(whoisdata string) map[string][]string {
	info := make(map[string][]string)
	lines := strings.Split(whoisdata, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		info[key] = append(info[key], value)
	}
	return info
}
