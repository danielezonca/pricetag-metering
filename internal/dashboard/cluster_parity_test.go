package dashboard

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// clusterGoldenHashes pins each unified template's cluster-mode render to the
// exact bytes origin/main served for that page. The PR contract is that
// cluster output stays byte-identical to main, so a correctly marked but
// whitespace- or content-drifted cluster block must fail CI instead of
// silently shipping a divergent page. The marker scan in mode_test.go cannot
// catch that class of drift; only a byte compare can.
var clusterGoldenHashes = map[string]string{
	"account.html":   "520f0dc518894ade5d0c5eb245228da0cff032e4a4ace5fde4dedb14e35472da",
	"admin.html":     "bba87e6775fb41fd9d87edf1f160636e208049a621debb26f4f4fd3490ad9e5c",
	"dashboard.html": "35fb6aaab2270da5fa3eb1e9e3409fa25ac75527785ee19e531d902388de9f6a",
	"manager.html":   "38387994b6bfba8691ad031f082e2af157b370340658e81a3d68cc149b34c399",
}

// TestClusterModeBytesMatchMain guards the byte-identical guarantee.
func TestClusterModeBytesMatchMain(t *testing.T) {
	for name, want := range clusterGoldenHashes {
		cluster := readMode(t, name, false)
		got := fmt.Sprintf("%x", sha256.Sum256(cluster))
		if got != want {
			t.Errorf("%s: cluster-mode bytes drifted from origin/main (sha256 %s != golden %s)", name, got, want)
		}
	}
}
