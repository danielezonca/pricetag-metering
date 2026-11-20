package dashboard

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
)

// readMode returns one deployment mode's rendering of a unified template:
// what the handler actually serves. Unmarked templates pass through
// unchanged, so it is safe for every embedded page.
func readMode(t *testing.T, name string, standalone bool) []byte {
	t.Helper()
	data, err := fs.ReadFile(FS, name)
	if err != nil {
		t.Fatal(err)
	}
	page, err := ForMode(data, standalone)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return page
}

func TestForModePassesThroughUnmarkedTemplates(t *testing.T) {
	page := []byte("<html>\n<body>hello</body>\n</html>\n")
	for _, standalone := range []bool{false, true} {
		out, err := ForMode(page, standalone)
		if err != nil {
			t.Fatalf("standalone=%v: %v", standalone, err)
		}
		if !bytes.Equal(out, page) {
			t.Fatalf("standalone=%v: unmarked template changed: %q", standalone, out)
		}
	}
}

func TestForModeResolvesBlocksInEveryMarkerSyntax(t *testing.T) {
	page := []byte(strings.Join([]string{
		"<style>",
		"/*MODE:cluster*/",
		"a{color:red}",
		"/*MODE:end*/",
		"/*MODE:standalone*/",
		"a{color:blue}",
		"/*MODE:end*/",
		"</style>",
		"<script>",
		"//MODE:cluster",
		"var x = 1;",
		"//MODE:end",
		"//MODE:standalone",
		"var x = 2;",
		"//MODE:end",
		"</script>",
		"<!--MODE:cluster-->",
		"<p>cluster only</p>",
		"<!--MODE:end-->",
		"<!--MODE:standalone-->",
		"<p>standalone only</p>",
		"<!--MODE:end-->",
		"<p>shared</p>",
	}, "\n"))

	cluster, err := ForMode(page, false)
	if err != nil {
		t.Fatal(err)
	}
	wantCluster := strings.Join([]string{
		"<style>",
		"a{color:red}",
		"</style>",
		"<script>",
		"var x = 1;",
		"</script>",
		"<p>cluster only</p>",
		"<p>shared</p>",
	}, "\n")
	if string(cluster) != wantCluster {
		t.Fatalf("cluster output mismatch:\n%q", cluster)
	}

	standalone, err := ForMode(page, true)
	if err != nil {
		t.Fatal(err)
	}
	wantStandalone := strings.Join([]string{
		"<style>",
		"a{color:blue}",
		"</style>",
		"<script>",
		"var x = 2;",
		"</script>",
		"<p>standalone only</p>",
		"<p>shared</p>",
	}, "\n")
	if string(standalone) != wantStandalone {
		t.Fatalf("standalone output mismatch:\n%q", standalone)
	}
}

func TestForModeRejectsMalformedMarkers(t *testing.T) {
	cases := map[string][]byte{
		"nested start":  []byte("//MODE:cluster\n//MODE:standalone\nx\n//MODE:end\n"),
		"unmatched end": []byte("//MODE:end\n"),
		"unclosed":      []byte("//MODE:cluster\nx\n"),
	}
	for name, page := range cases {
		if _, err := ForMode(page, false); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

// A typo'd marker (for example "//MODE:standalon") matches neither marker
// regex, so ForMode would silently emit it into both renders: the output
// leak check cannot flag it because it only recognizes well-formed markers.
// The byte-compare guards cluster output against main; this scan guards the
// source of every unified template so a typo fails at test time.
func TestUnifiedTemplateMarkerLinesAreWellFormed(t *testing.T) {
	for _, name := range []string{"admin.html", "dashboard.html", "manager.html", "account.html"} {
		data, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "MODE:") {
				continue
			}
			if !modeStartRe.MatchString(line) && !modeEndRe.MatchString(line) {
				t.Fatalf("%s: marker-like line matches no marker form: %q", name, line)
			}
		}
	}
}

func TestUnifiedTemplatesRenderMarkerFreeForBothModes(t *testing.T) {
	for _, name := range []string{"admin.html", "dashboard.html", "manager.html", "account.html"} {
		data, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var cluster, standalone []byte
		for _, isStandalone := range []bool{false, true} {
			out, err := ForMode(data, isStandalone)
			if err != nil {
				t.Fatalf("%s standalone=%v: %v", name, isStandalone, err)
			}
			if len(out) == 0 {
				t.Fatalf("%s standalone=%v: empty output", name, isStandalone)
			}
			for _, line := range strings.Split(string(out), "\n") {
				if modeStartRe.MatchString(line) || modeEndRe.MatchString(line) {
					t.Fatalf("%s standalone=%v: marker leaked into output: %q", name, isStandalone, line)
				}
			}
			if isStandalone {
				standalone = out
			} else {
				cluster = out
			}
		}
		if name == "account.html" {
			// Main currently disables the account key flow in both deployment
			// modes while its identity flow is updated.
			if !bytes.Equal(cluster, standalone) {
				t.Fatalf("%s: expected identical Coming soon page in both modes", name)
			}
		} else if bytes.Equal(cluster, standalone) {
			t.Fatalf("%s: both modes render identically", name)
		}
	}
}

func TestUnifiedAdminKeepsServeAdminPreconditions(t *testing.T) {
	data, err := fs.ReadFile(FS, "admin.html")
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := ForMode(data, true)
	if err != nil {
		t.Fatal(err)
	}
	// ServeAdmin activates the management console by replacing this exact
	// marker; its absence must stay a hard failure rather than drift silently.
	if !strings.Contains(string(standalone), "data-managed hidden") {
		t.Fatal("standalone admin output lost the data-managed hidden activation marker")
	}
	for _, marker := range []string{
		"<!-- MANAGED_KEYS -->",
		"<!-- MANAGED_USERS -->",
		"<!-- MANAGED_BUDGETS -->",
		"<!-- MANAGED_PRICES -->",
		"<!-- MANAGED_SCRIPT -->",
	} {
		if !strings.Contains(string(standalone), marker) {
			t.Fatalf("standalone admin output lost fragment marker %s", marker)
		}
	}
}
