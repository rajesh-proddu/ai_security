package core

import "sort"

// Normalization rewrites text — it decodes, strips and folds characters — so a
// span found in normalized text does not line up with the payload the gateway
// holds. An OffsetMap carries the correspondence back, so a redaction is applied
// to the right bytes of the original.

// OffsetSegment maps one run of normalized bytes onto the original bytes it
// came from. When the two runs have the same length the mapping is positional;
// when they differ (an HTML entity collapsing to one rune, a base64 token
// expanding to its payload) any offset inside the run maps to the whole
// original run, because no finer correspondence exists.
type OffsetSegment struct {
	NormStart int
	NormEnd   int
	OrigStart int
	OrigEnd   int
}

func (s OffsetSegment) positional() bool {
	return s.NormEnd-s.NormStart == s.OrigEnd-s.OrigStart
}

// OffsetMap maps normalized offsets back to original offsets. The zero value is
// the identity map, which is what an untouched part gets.
type OffsetMap struct {
	segs []OffsetSegment
}

// NewOffsetMap builds a map from contiguous, ascending segments.
func NewOffsetMap(segs []OffsetSegment) OffsetMap {
	if len(segs) == 0 {
		return OffsetMap{}
	}
	return OffsetMap{segs: segs}
}

// Identity reports whether the map leaves offsets unchanged.
func (m OffsetMap) Identity() bool { return len(m.segs) == 0 }

// Segments returns the map's segments.
func (m OffsetMap) Segments() []OffsetSegment { return m.segs }

// Span maps a half-open range of normalized offsets to the original range that
// produced it. The result is always a valid half-open range.
func (m OffsetMap) Span(normStart, normEnd int) (int, int) {
	if m.Identity() {
		return normStart, normEnd
	}
	start := m.start(normStart)
	end := m.end(normEnd)
	if end < start {
		end = start
	}
	return start, end
}

func (m OffsetMap) start(p int) int {
	if p <= m.segs[0].NormStart {
		return m.segs[0].OrigStart
	}
	last := m.segs[len(m.segs)-1]
	if p >= last.NormEnd {
		return last.OrigEnd
	}
	seg := m.segs[m.search(p)]
	if seg.positional() {
		return seg.OrigStart + (p - seg.NormStart)
	}
	return seg.OrigStart
}

func (m OffsetMap) end(p int) int {
	if p <= m.segs[0].NormStart {
		return m.segs[0].OrigStart
	}
	last := m.segs[len(m.segs)-1]
	if p >= last.NormEnd {
		return last.OrigEnd
	}
	// p is exclusive, so it belongs to the segment holding p-1.
	seg := m.segs[m.search(p-1)]
	if seg.positional() {
		return seg.OrigStart + (p - seg.NormStart)
	}
	return seg.OrigEnd
}

// search returns the index of the segment containing the normalized offset p,
// which callers have already bounded to [segs[0].NormStart, last.NormEnd).
func (m OffsetMap) search(p int) int {
	i := sort.Search(len(m.segs), func(i int) bool { return m.segs[i].NormEnd > p })
	if i == len(m.segs) {
		return len(m.segs) - 1
	}
	return i
}

// ComposeOffsets chains two normalization passes: outer maps the final text
// onto the intermediate text, inner maps the intermediate text onto the
// original. The result maps the final text onto the original.
func ComposeOffsets(outer, inner OffsetMap) OffsetMap {
	switch {
	case outer.Identity():
		return inner
	case inner.Identity():
		return outer
	}
	segs := make([]OffsetSegment, 0, len(outer.segs)+len(inner.segs))
	innerEnd := inner.segs[len(inner.segs)-1].NormEnd
	for _, s := range outer.segs {
		// A positional outer run may span several inner segments. Split it at
		// inner boundaries, or a run that is exact in both passes would be
		// widened to the union of everything it crosses — over-redaction.
		if !s.positional() || s.OrigStart >= innerEnd {
			origStart, origEnd := inner.Span(s.OrigStart, s.OrigEnd)
			segs = append(segs, OffsetSegment{s.NormStart, s.NormEnd, origStart, origEnd})
			continue
		}
		for mid := s.OrigStart; mid < s.OrigEnd; {
			cut := s.OrigEnd
			if in := inner.segs[inner.search(mid)]; in.NormEnd < cut && in.NormEnd > mid {
				cut = in.NormEnd
			}
			origStart, origEnd := inner.Span(mid, cut)
			segs = append(segs, OffsetSegment{
				NormStart: s.NormStart + (mid - s.OrigStart),
				NormEnd:   s.NormStart + (cut - s.OrigStart),
				OrigStart: origStart,
				OrigEnd:   origEnd,
			})
			mid = cut
		}
	}
	return NewOffsetMap(segs)
}

// MergeSpans returns the spans as a non-overlapping, ascending set, per part.
// Detectors routinely overlap — a card number inside a JSON value matched by
// both `pii` and `secrets`, say — and applying overlapping redactions to one
// payload corrupts it.
func MergeSpans(spans []Span) []Span {
	if len(spans) == 0 {
		return nil
	}
	sorted := make([]Span, len(spans))
	copy(sorted, spans)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Part != sorted[j].Part {
			return sorted[i].Part < sorted[j].Part
		}
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End < sorted[j].End
	})

	merged := []Span{sorted[0]}
	for _, s := range sorted[1:] {
		last := &merged[len(merged)-1]
		if s.Part == last.Part && s.Start <= last.End {
			if s.End > last.End {
				last.End = s.End
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}
