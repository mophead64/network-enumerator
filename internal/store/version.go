package store

import (
	"strconv"
	"strings"
)

// versionLess reports whether a is an older version than b, comparing
// numeric components left to right (e.g. "7.4" < "8.9p1", "2.4.7" <
// "2.4.41"). Real service version strings aren't strict semver — trailing
// suffixes like "p1" or "rc2" are common — so this isn't a full parser: it
// splits on any run of non-digit characters, compares the resulting numbers
// pairwise, and treats a missing trailing component as 0. Good enough for
// "is this older than the version I'm worried about" triage; not a general
// version-ordering algorithm.
func versionLess(a, b string) bool {
	an, bn := versionNumbers(a), versionNumbers(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		var av, bv int
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}

func versionNumbers(v string) []int {
	var out []int
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		n, _ := strconv.Atoi(cur.String())
		out = append(out, n)
		cur.Reset()
	}
	for _, r := range v {
		if r >= '0' && r <= '9' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}
