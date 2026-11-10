package version

import (
	"fmt"
	"io"
	"time"
)

// progressInterval is how often the download line is redrawn. Redrawing on every
// chunk costs terminal work that the transfer does not need.
const progressInterval = 200 * time.Millisecond

// progressWriter draws one line of download progress. A nil writer discards
// everything, so a download on a pipe or a log stays silent.
type progressWriter struct {
	w     io.Writer
	total int64
	done  int64
	last  time.Time
}

func newProgressWriter(w io.Writer, total int64) *progressWriter {
	if w == nil {
		return nil
	}
	return &progressWriter{w: w, total: total}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	if p == nil {
		return len(b), nil
	}
	p.done += int64(len(b))
	if time.Since(p.last) >= progressInterval {
		p.last = time.Now()
		p.draw("\r")
	}
	return len(b), nil
}

// Finish draws the final line and ends it, so later output starts on a new line.
func (p *progressWriter) Finish() {
	if p == nil {
		return
	}
	p.draw("\n")
}

func (p *progressWriter) draw(end string) {
	line := "  downloaded " + humanBytes(p.done)
	if p.total > 0 {
		line += fmt.Sprintf(" / %s (%d%%)", humanBytes(p.total), p.done*100/p.total)
	}
	// The padding clears a longer previous line.
	fmt.Fprintf(p.w, "\r%-72s%s", line, end)
}

// humanBytes renders a byte count in binary units.
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(1024), 0
	for m := n / 1024; m >= 1024; m /= 1024 {
		div *= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
