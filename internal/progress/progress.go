// Package progress renders lightweight, dependency-free progress feedback
// on an io.Writer (typically os.Stderr). It is intentionally self-contained
// so this repository has zero third-party dependencies.
package progress

import (
	"fmt"
	"io"
	"strings"
)

const barWidth = 24

// WriteToolProgress prints a single-line progress update in the form:
//
//	[####--------------------]  16% (1/6) domain-whois
//
// It is safe to call with a nil writer or a total <= 0; in both cases the
// call is a no-op so callers don't need to guard every invocation.
func WriteToolProgress(w io.Writer, current, total int, stage string) {
	if w == nil || total <= 0 {
		return
	}
	if current > total {
		current = total
	}
	if current < 0 {
		current = 0
	}

	percent := float64(current) / float64(total)
	filled := int(percent * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}

	bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)

	fmt.Fprintf(w, "\r[%s] %3d%% (%d/%d) %s", bar, int(percent*100), current, total, stage)
	if current >= total {
		fmt.Fprintln(w)
	}
}
