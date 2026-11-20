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
	"account.html":   "32d69e97bc1f687c319cf8446d5673b9efe5165e8ca78f7969344ca8f0431e97",
	"admin.html":     "78324e1dd892925a84e7c50454b7e10f3a53e92aec60953a5eb757a7fea8438b",
	"dashboard.html": "b424f525fbffc23189f9cd74978191fd3ae9e7eaa478273aff3f5a83d42c6477",
	"manager.html":   "72bbba6e5825be481a6c7061b09e4e2aebc1049d58a48c2d2353f859597301d8",
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
