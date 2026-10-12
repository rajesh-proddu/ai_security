package detect

// A small Aho-Corasick automaton, as DESIGN §3.3 specifies for custom_dict:
// one pass over the text regardless of how many terms a tenant configures.
// Matching is case-insensitive, over lowercased bytes.

type acNode struct {
	next   map[byte]int
	fail   int
	output []int // indexes into the term list
}

type ahoCorasick struct {
	nodes []acNode
	terms []string
}

func newAhoCorasick(terms []string) *ahoCorasick {
	ac := &ahoCorasick{nodes: []acNode{{next: map[byte]int{}}}}
	for _, t := range terms {
		if t == "" {
			continue
		}
		ac.add(lower(t))
	}
	ac.build()
	return ac
}

func (ac *ahoCorasick) add(term string) {
	cur := 0
	for i := range len(term) {
		c := term[i]
		next, ok := ac.nodes[cur].next[c]
		if !ok {
			next = len(ac.nodes)
			ac.nodes = append(ac.nodes, acNode{next: map[byte]int{}})
			ac.nodes[cur].next[c] = next
		}
		cur = next
	}
	ac.terms = append(ac.terms, term)
	ac.nodes[cur].output = append(ac.nodes[cur].output, len(ac.terms)-1)
}

// build wires the failure links breadth-first.
func (ac *ahoCorasick) build() {
	queue := make([]int, 0, len(ac.nodes))
	for c, n := range ac.nodes[0].next {
		ac.nodes[n].fail = 0
		queue = append(queue, n)
		_ = c
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c, n := range ac.nodes[cur].next {
			f := ac.nodes[cur].fail
			for f != 0 {
				if _, ok := ac.nodes[f].next[c]; ok {
					break
				}
				f = ac.nodes[f].fail
			}
			if nf, ok := ac.nodes[f].next[c]; ok && nf != n {
				ac.nodes[n].fail = nf
			} else {
				ac.nodes[n].fail = 0
			}
			ac.nodes[n].output = append(ac.nodes[n].output, ac.nodes[ac.nodes[n].fail].output...)
			queue = append(queue, n)
		}
	}
}

// match is one term occurrence: byte offsets into the text and the term index.
type match struct {
	start, end, term int
}

// find returns every occurrence of every term, in order of end offset.
func (ac *ahoCorasick) find(text string) []match {
	if len(ac.terms) == 0 {
		return nil
	}
	var out []match
	cur := 0
	for i := range len(text) {
		c := lowerByte(text[i])
		for {
			if n, ok := ac.nodes[cur].next[c]; ok {
				cur = n
				break
			}
			if cur == 0 {
				break
			}
			cur = ac.nodes[cur].fail
		}
		for _, t := range ac.nodes[cur].output {
			out = append(out, match{start: i + 1 - len(ac.terms[t]), end: i + 1, term: t})
		}
	}
	return out
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = lowerByte(b[i])
	}
	return string(b)
}
