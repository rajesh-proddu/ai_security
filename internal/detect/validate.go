package detect

import "strings"

// Checksum validators for the India pack of DESIGN decision 4. A checksum turns
// a pattern that matches any 12 digits into one that matches an Aadhaar, which
// is the difference between a usable detector and a noise generator.

// verhoeffD is the multiplication table of the dihedral group D5.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffP is the permutation table.
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// Verhoeff reports whether the digit string carries a valid Verhoeff check
// digit, the scheme UIDAI uses for Aadhaar numbers.
func Verhoeff(digits string) bool {
	c := 0
	for i, n := 0, len(digits); i < n; i++ {
		d := int(digits[n-i-1] - '0')
		if d < 0 || d > 9 {
			return false
		}
		c = verhoeffD[c][verhoeffP[i%8][d]]
	}
	return c == 0
}

// Luhn reports whether the digit string carries a valid Luhn check digit, used
// by payment cards.
func Luhn(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return len(digits) > 0 && sum%10 == 0
}

const gstinAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GSTIN reports whether a 15-character GSTIN carries a valid check character.
// The first 14 characters are weighted alternately 1 and 2 in base 36.
func GSTIN(s string) bool {
	if len(s) != 15 {
		return false
	}
	sum := 0
	for i := range 14 {
		v := strings.IndexByte(gstinAlphabet, s[i])
		if v < 0 {
			return false
		}
		weight := 1
		if i%2 == 1 {
			weight = 2
		}
		p := v * weight
		sum += p/36 + p%36
	}
	want := gstinAlphabet[(36-sum%36)%36]
	return s[14] == want
}

// digitsOnly strips the separators people write inside numbers.
func digitsOnly(s string) string {
	var b strings.Builder
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
