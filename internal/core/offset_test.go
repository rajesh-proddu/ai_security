package core

import "testing"

func TestOffsetMapSpan(t *testing.T) {
	// Original: "ab&amp;cd" (9 bytes). Normalized: "ab&cd" (5 bytes).
	entity := NewOffsetMap([]OffsetSegment{
		{NormStart: 0, NormEnd: 2, OrigStart: 0, OrigEnd: 2}, // "ab"
		{NormStart: 2, NormEnd: 3, OrigStart: 2, OrigEnd: 7}, // "&amp;" → "&"
		{NormStart: 3, NormEnd: 5, OrigStart: 7, OrigEnd: 9}, // "cd"
	})
	// Original: "x​y" (5 bytes, zero-width space is 3). Normalized: "xy".
	stripped := NewOffsetMap([]OffsetSegment{
		{NormStart: 0, NormEnd: 1, OrigStart: 0, OrigEnd: 1},
		{NormStart: 1, NormEnd: 2, OrigStart: 4, OrigEnd: 5},
	})

	tests := []struct {
		name       string
		m          OffsetMap
		start, end int
		wantStart  int
		wantEnd    int
	}{
		{"identity", OffsetMap{}, 3, 7, 3, 7},
		{"positional run", entity, 0, 2, 0, 2},
		{"inside positional run", entity, 1, 2, 1, 2},
		{"collapsed entity maps to whole entity", entity, 2, 3, 2, 7},
		{"run after entity is shifted", entity, 3, 5, 7, 9},
		{"span across the entity", entity, 1, 4, 1, 8},
		{"whole text", entity, 0, 5, 0, 9},
		{"empty span at end", entity, 5, 5, 9, 9},
		{"past the end clamps", entity, 4, 50, 8, 9},
		{"stripped char is covered by a span across it", stripped, 0, 2, 0, 5},
		{"span after the stripped char", stripped, 1, 2, 4, 5},
		{"span before the stripped char", stripped, 0, 1, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, e := tt.m.Span(tt.start, tt.end)
			if s != tt.wantStart || e != tt.wantEnd {
				t.Fatalf("Span(%d,%d) = (%d,%d), want (%d,%d)", tt.start, tt.end, s, e, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

// An expansion — one original token producing more normalized bytes, as base64
// decoding does — must map every normalized offset inside it to the whole token.
func TestOffsetMapExpansion(t *testing.T) {
	// Original: "k=aGk=" ; normalized "k=hi" where "aGk=" (orig 2..6) decoded to "hi" (norm 2..4).
	m := NewOffsetMap([]OffsetSegment{
		{NormStart: 0, NormEnd: 2, OrigStart: 0, OrigEnd: 2},
		{NormStart: 2, NormEnd: 4, OrigStart: 2, OrigEnd: 6},
	})
	for _, span := range [][2]int{{2, 3}, {3, 4}, {2, 4}} {
		s, e := m.Span(span[0], span[1])
		if s != 2 || e != 6 {
			t.Errorf("Span(%d,%d) = (%d,%d), want (2,6)", span[0], span[1], s, e)
		}
	}
}

func TestComposeOffsets(t *testing.T) {
	// Pass 1 (inner): original "a&amp;b​c" → "a&b​c"
	//   orig: a[0,1) &amp;[1,6) b[6,7) ZWSP[7,10) c[10,11)
	//   mid:  a[0,1) &[1,2)     b[2,3) ZWSP[3,6)  c[6,7)
	inner := NewOffsetMap([]OffsetSegment{
		{NormStart: 0, NormEnd: 1, OrigStart: 0, OrigEnd: 1},
		{NormStart: 1, NormEnd: 2, OrigStart: 1, OrigEnd: 6},
		{NormStart: 2, NormEnd: 7, OrigStart: 6, OrigEnd: 11},
	})
	// Pass 2 (outer): mid "a&b​c" → final "a&bc" (ZWSP stripped)
	outer := NewOffsetMap([]OffsetSegment{
		{NormStart: 0, NormEnd: 3, OrigStart: 0, OrigEnd: 3},
		{NormStart: 3, NormEnd: 4, OrigStart: 6, OrigEnd: 7},
	})
	m := ComposeOffsets(outer, inner)

	tests := []struct {
		name       string
		start, end int
		wantStart  int
		wantEnd    int
	}{
		{"a", 0, 1, 0, 1},
		{"& is the whole entity", 1, 2, 1, 6},
		{"b", 2, 3, 6, 7},
		{"c skips entity and zero-width", 3, 4, 10, 11},
		{"b..c covers the stripped char", 2, 4, 6, 11},
		{"everything", 0, 4, 0, 11},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, e := m.Span(tt.start, tt.end)
			if s != tt.wantStart || e != tt.wantEnd {
				t.Fatalf("Span(%d,%d) = (%d,%d), want (%d,%d)", tt.start, tt.end, s, e, tt.wantStart, tt.wantEnd)
			}
		})
	}

	if !ComposeOffsets(OffsetMap{}, OffsetMap{}).Identity() {
		t.Error("identity ∘ identity must be identity")
	}
	if got := ComposeOffsets(OffsetMap{}, inner); len(got.Segments()) != len(inner.Segments()) {
		t.Error("identity outer must return inner")
	}
}

func TestMergeSpans(t *testing.T) {
	tests := []struct {
		name string
		in   []Span
		want []Span
	}{
		{"none", nil, nil},
		{"one", []Span{{0, 1, 3}}, []Span{{0, 1, 3}}},
		{"overlap", []Span{{0, 1, 5}, {0, 3, 8}}, []Span{{0, 1, 8}}},
		{"touching merge", []Span{{0, 1, 3}, {0, 3, 5}}, []Span{{0, 1, 5}}},
		{"contained", []Span{{0, 1, 10}, {0, 3, 4}}, []Span{{0, 1, 10}}},
		{"identical (base64 token + its decode)", []Span{{0, 2, 6}, {0, 2, 6}}, []Span{{0, 2, 6}}},
		{"disjoint unsorted", []Span{{0, 7, 9}, {0, 1, 2}}, []Span{{0, 1, 2}, {0, 7, 9}}},
		{"parts never merge", []Span{{1, 0, 5}, {0, 0, 5}}, []Span{{0, 0, 5}, {1, 0, 5}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeSpans(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("MergeSpans(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("MergeSpans(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}
