package normalize

import (
	"strings"

	"github.com/rajesh-proddu/ai_security/internal/core"
)

// builder writes one pass's output and records, for every byte written, which
// input bytes it came from. Every output byte is covered by exactly one segment,
// with no gaps, which is what core.OffsetMap assumes.
type builder struct {
	out     strings.Builder
	segs    []core.OffsetSegment
	changed bool
}

// keep copies in[start:end] unchanged.
func (b *builder) keep(in string, start, end int) {
	if start >= end {
		return
	}
	n := b.out.Len()
	b.out.WriteString(in[start:end])
	if k := len(b.segs) - 1; k >= 0 {
		last := &b.segs[k]
		// Extend a positional run that this continues, so an unchanged text
		// stays one segment rather than one per call.
		if last.NormEnd == n && last.OrigEnd == start && last.NormEnd-last.NormStart == last.OrigEnd-last.OrigStart {
			last.NormEnd += end - start
			last.OrigEnd = end
			return
		}
	}
	b.segs = append(b.segs, core.OffsetSegment{NormStart: n, NormEnd: n + end - start, OrigStart: start, OrigEnd: end})
}

// replace writes repl in place of input bytes [start, end). An empty repl
// drops the input bytes.
func (b *builder) replace(repl string, start, end int) {
	b.changed = true
	if repl == "" {
		return
	}
	n := b.out.Len()
	b.out.WriteString(repl)
	b.segs = append(b.segs, core.OffsetSegment{NormStart: n, NormEnd: n + len(repl), OrigStart: start, OrigEnd: end})
}

func (b *builder) result(in string) (string, core.OffsetMap) {
	if !b.changed {
		return in, core.OffsetMap{}
	}
	return b.out.String(), core.NewOffsetMap(b.segs)
}
