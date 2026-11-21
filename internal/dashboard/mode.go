package dashboard

import (
	"errors"
	"regexp"
	"strings"
)

var (
	modeStartRe = regexp.MustCompile(`^\s*(?:<!--|//|/\*)MODE:(cluster|standalone)(?:-->|\*/)?\s*$`)
	modeEndRe   = regexp.MustCompile(`^\s*(?:<!--|//|/\*)MODE:end(?:-->|\*/)?\s*$`)
)

// ForMode resolves mode-marked template blocks for the deployment mode.
//
// Unified templates mark deployment-mode-specific line ranges with markers
// whose syntax is valid in their surrounding context: HTML comments in
// markup, // comments inside <script>, and /* */ comments inside <style>.
//
//	<!--MODE:cluster--> ... <!--MODE:end-->
//	//MODE:standalone ... //MODE:end
//	/*MODE:cluster*/ ... /*MODE:end*/
//
// ForMode removes the blocks that do not apply to the requested mode and
// strips every marker line. A template without markers passes through
// unchanged; a marked template renders exactly the line set it was unified
// from, so cluster mode keeps serving the pre-consolidation cluster bytes.
func ForMode(page []byte, standalone bool) ([]byte, error) {
	mode := "cluster"
	if standalone {
		mode = "standalone"
	}
	lines := strings.Split(string(page), "\n")
	out := make([]string, 0, len(lines))
	keeping := true
	depth := 0
	for _, line := range lines {
		if m := modeStartRe.FindStringSubmatch(line); m != nil {
			if depth != 0 {
				return nil, errors.New("dashboard: nested MODE marker")
			}
			keeping = m[1] == mode
			depth = 1
			continue
		}
		if modeEndRe.MatchString(line) {
			if depth != 1 {
				return nil, errors.New("dashboard: unmatched MODE end marker")
			}
			keeping = true
			depth = 0
			continue
		}
		if keeping {
			out = append(out, line)
		}
	}
	if depth != 0 {
		return nil, errors.New("dashboard: unclosed MODE block")
	}
	return []byte(strings.Join(out, "\n")), nil
}
