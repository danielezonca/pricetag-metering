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
	"account.html":   "8a2e5dfb2e9960948263bcee4252cb4efb93d11cf86dd94dd6af76e1ab5779fc",
	"admin.html":     "c077dc6d0e5182cc9de7babd4071887d81ac369c1f0e71bdc4f40d8bd3f6b7aa",
	"dashboard.html": "08b1580af7c534702dcd557cb0a6647965fdef48d5281074d0a4646736ce912c",
	"manager.html":   "377a3071445fc68f451b969bfb2dd7cbc7eadae1eda8aea1bda968faced084c0",
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
