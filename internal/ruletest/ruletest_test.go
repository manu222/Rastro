// Package ruletest verifies that every detection rule in this repository still
// matches exactly what its manifest says it should.
//
// It runs Hayabusa once over the whole dataset with every rule loaded, then
// checks each manifest in tests/ against the result. Two things are asserted:
//
//   - each listed sample produces the stated number of hits, and
//   - the repository-wide total for the rule matches.
//
// The second one is what catches a broken exclusion filter, which shows up as
// MORE hits rather than fewer and would pass a positive-only test.
package ruletest

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// manifest mirrors the YAML files under tests/.
type manifest struct {
	name   string // file name, for error messages
	Rule   string `yaml:"rule"`
	RuleID string `yaml:"rule_id"`
	Expect []struct {
		File string `yaml:"file"`
		Hits int    `yaml:"hits"`
		Note string `yaml:"note"`
	} `yaml:"expect"`
	Total int `yaml:"total"`

	// NegativeControl, when present, requires the rule's selection to match
	// something once every exclusion filter is neutralised. It is what separates
	// a rule that correctly finds nothing from a rule that can never fire.
	NegativeControl *struct {
		MinHits int `yaml:"min_hits_without_filters"`
	} `yaml:"negative_control"`
}

// detection is one row of Hayabusa's verbose CSV output, reduced to the fields
// the assertions need.
type detection struct {
	ruleID string
	evtx   string // path relative to the dataset root, forward slashes
}

func TestRulesMatchTheirManifests(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("cannot locate repository root: %v", err)
	}

	datasets := filepath.Join(root, "datasets")
	if !isDir(datasets) {
		skipOrFail(t, "datasets/ not found. Clone the sample set first — see tests/README.md")
		return
	}

	hayabusa, err := findHayabusa(root)
	if err != nil {
		skipOrFail(t, fmt.Sprintf("hayabusa not found: %v", err))
		return
	}

	manifests, err := loadManifests(filepath.Join(root, "tests"))
	if err != nil {
		t.Fatalf("cannot read manifests: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("no manifests found under tests/")
	}

	detections, err := runHayabusa(t, hayabusa, filepath.Join(root, "rules"), datasets)
	if err != nil {
		t.Fatalf("hayabusa run failed: %v", err)
	}

	for _, m := range manifests {
		t.Run(m.name, func(t *testing.T) {
			// Count this rule's hits, grouped by the file they came from.
			perFile := map[string]int{}
			total := 0
			for _, d := range detections {
				if d.ruleID != m.RuleID {
					continue
				}
				perFile[d.evtx]++
				total++
			}

			for _, want := range m.Expect {
				key := filepath.ToSlash(want.File)
				got := perFile[key]
				if got != want.Hits {
					t.Errorf("%s\n  want %d hit(s), got %d\n  sample: %s",
						want.Note, want.Hits, got, key)
				}
				delete(perFile, key)
			}

			// Anything left over fired on a sample the manifest does not list.
			for file, n := range perFile {
				t.Errorf("unexpected match: %d hit(s) in %s, not listed in the manifest", n, file)
			}

			if m.NegativeControl != nil {
				assertNegativeControl(t, hayabusa, root, datasets, m)
			}

			if total != m.Total {
				t.Errorf("repository-wide total: want %d, got %d\n"+
					"  fewer than expected means the rule stopped detecting something;\n"+
					"  more means an exclusion filter broke and it is firing on legitimate activity",
					m.Total, total)
			}
		})
	}
}

// runHayabusa executes one scan over the whole dataset with every rule loaded
// and returns the detections. The verbose profile is required: it is the only
// one that reports which evtx file each detection came from.
func runHayabusa(t *testing.T, bin, rules, datasets string) ([]detection, error) {
	t.Helper()

	out := filepath.Join(t.TempDir(), "detections.csv")
	cmd := exec.Command(bin,
		"dfir-timeline",
		"-d", datasets,
		"-r", rules,
		"-p", "verbose",
		"-o", out,
		"-a", // scan every evtx file: hayabusa's channel filter skips files it
		//       believes no loaded rule can match, which both drops real
		//       detections and makes a rule's hit count depend on which other
		//       rules happen to be loaded alongside it.
		"-w", // no wizard
		"-s", // sort, required by dfir-timeline
		"-q", // no banner
		"-C", // clobber an existing output file
		"-K", // no colour codes in the output
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(string(combined), 800))
	}

	f, err := os.Open(out)
	if err != nil {
		// No detections at all means hayabusa writes no file.
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // Details can contain stray field counts
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing hayabusa output: %w", err)
	}
	if len(records) < 2 {
		return nil, nil
	}

	idx := map[string]int{}
	for i, h := range records[0] {
		idx[h] = i
	}
	ruleCol, ok1 := idx["RuleID"]
	evtxCol, ok2 := idx["EvtxFile"]
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("hayabusa output lacks RuleID or EvtxFile; is the verbose profile still available? columns: %v", records[0])
	}

	var out2 []detection
	for _, row := range records[1:] {
		if ruleCol >= len(row) || evtxCol >= len(row) {
			continue
		}
		out2 = append(out2, detection{
			ruleID: strings.TrimSpace(row[ruleCol]),
			evtx:   relativeToDataset(row[evtxCol], datasets),
		})
	}
	return out2, nil
}

// relativeToDataset turns the absolute path hayabusa reports into the same
// forward-slash relative form the manifests use, so the comparison works the
// same on Windows and Linux.
func relativeToDataset(p, datasets string) string {
	p = filepath.ToSlash(strings.TrimSpace(p))
	base := filepath.ToSlash(datasets)
	if rel, err := filepath.Rel(base, filepath.FromSlash(p)); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	// Fall back to trimming the prefix textually.
	if i := strings.Index(p, base); i >= 0 {
		return strings.TrimPrefix(p[i+len(base):], "/")
	}
	return p
}

func loadManifests(dir string) ([]manifest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	var out []manifest
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var m manifest
		if err := yaml.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		if m.RuleID == "" {
			return nil, fmt.Errorf("%s: missing rule_id", filepath.Base(p))
		}
		m.name = strings.TrimSuffix(filepath.Base(p), ".yml")
		out = append(out, m)
	}
	return out, nil
}

// findHayabusa looks for the binary, preferring an explicit override so CI can
// point at wherever it installed it.
func findHayabusa(root string) (string, error) {
	if p := os.Getenv("HAYABUSA"); p != "" {
		if fileExists(p) {
			return p, nil
		}
		return "", fmt.Errorf("HAYABUSA is set to %q but that file does not exist", p)
	}
	pattern := filepath.Join(root, "tools", "hayabusa", "hayabusa-*")
	if runtime.GOOS == "windows" {
		pattern += ".exe"
	}
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		if fileExists(m) {
			return m, nil
		}
	}
	return "", fmt.Errorf("nothing matched %s and HAYABUSA is unset", pattern)
}

// skipOrFail keeps a developer without the tools installed from seeing red,
// while making sure CI never reports success because it silently skipped.
func skipOrFail(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("RASTRO_REQUIRE_TOOLS") != "" {
		t.Fatalf("%s (RASTRO_REQUIRE_TOOLS is set, so this is a failure)", reason)
	}
	t.Skip(reason + " — skipping")
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("walked up to the filesystem root without finding go.mod")
		}
		dir = parent
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// neverMatches is substituted for every value inside a filter block. No event
// field can hold it, so the filters stay syntactically valid while excluding
// nothing. Rewriting the condition instead would be brittle; neutralising the
// values works whatever shape the filters have.
const neverMatches = "RASTRO_NEGATIVE_CONTROL_SENTINEL"

// assertNegativeControl re-runs one rule with its exclusions disabled and
// requires the selection to match. A rule that still finds nothing was never
// matching anything to begin with, and its zero-hit result meant nothing.
func assertNegativeControl(t *testing.T, bin, root, datasets string, m manifest) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m.Rule)))
	if err != nil {
		t.Errorf("negative control: cannot read rule: %v", err)
		return
	}

	// The rule is edited as a YAML tree rather than decoded into Go types. A
	// round trip through map[string]interface{} rewrites values it thinks it
	// understands — notably turning the `date: 2026-09-11` field into a full
	// RFC3339 timestamp, which Sigma then rejects. Editing nodes preserves every
	// scalar exactly as written.
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Errorf("negative control: cannot parse rule: %v", err)
		return
	}
	if len(doc.Content) == 0 {
		t.Errorf("negative control: rule is empty")
		return
	}

	detection := mappingValue(doc.Content[0], "detection")
	if detection == nil {
		t.Errorf("negative control: rule has no detection block")
		return
	}

	neutralised := 0
	// A mapping node stores keys and values as alternating children.
	for i := 0; i+1 < len(detection.Content); i += 2 {
		key := detection.Content[i].Value
		if !strings.HasPrefix(key, "filter") {
			continue
		}
		blankOut(detection.Content[i+1])
		neutralised++
	}
	if neutralised == 0 {
		t.Errorf("negative control declared but the rule has no filter blocks to disable")
		return
	}

	rewritten, err := yaml.Marshal(&doc)
	if err != nil {
		t.Errorf("negative control: cannot serialise rewritten rule: %v", err)
		return
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), rewritten, 0o644); err != nil {
		t.Errorf("negative control: cannot write rewritten rule: %v", err)
		return
	}

	found, err := runHayabusa(t, bin, dir, datasets)
	if err != nil {
		t.Errorf("negative control: hayabusa run failed: %v", err)
		return
	}

	hits := 0
	for _, d := range found {
		if d.ruleID == m.RuleID {
			hits++
		}
	}

	if hits < m.NegativeControl.MinHits {
		t.Errorf("negative control failed: with every filter disabled the rule matched %d event(s), expected at least %d.\n"+
			"  The selection is not matching anything, so this rule cannot fire under any\n"+
			"  circumstances and its zero-hit result proves nothing. Check field names and operators.",
			hits, m.NegativeControl.MinHits)
	}
}

// mappingValue returns the value node for a key in a YAML mapping.
func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// blankOut replaces every scalar under a node with the sentinel, leaving the
// structure intact so the rule still parses.
func blankOut(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		n.Value = neverMatches
		n.Tag = "!!str"
		n.Style = 0
		return
	}
	for _, child := range n.Content {
		blankOut(child)
	}
}
