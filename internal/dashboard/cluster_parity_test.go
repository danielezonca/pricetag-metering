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
	"account.html":   "baa97723f8ff23957549f865f188b00290b61639819354377e6f268ea52851af",
	"admin.html":     "bba87e6775fb41fd9d87edf1f160636e208049a621debb26f4f4fd3490ad9e5c",
	"dashboard.html": "98e8d866c495ee51ea7a63e9748c6ce2f32a886cbdd50e3aff187bb3e499911b",
	"manager.html":   "e61803baa41434fb090bd7122e4278ff8d2994be744f364a833dacc7ea5dfff5",
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
