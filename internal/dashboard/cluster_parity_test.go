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
	"admin.html":     "5ce2fa9a11e96fd5a159bed8ca478b7d0269a493c76c22597c3caf0f00bb29e2",
	"dashboard.html": "8a84f079915d7d48d9b8d00c050502ca9a2486e92e25a3c9ea9139d73c245cd0",
	"manager.html":   "7a3f9df49127fe5a3e11c92a984ba6eedecbd2c01cb0cad9107f29ea288b61da",
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
