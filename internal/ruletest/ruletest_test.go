// Package ruletest verifies that every detection rule in this repository still
// matches exactly what its manifest says it should.
//
// There are three engines, because no single one reads every kind of evidence.
// Hayabusa reads Windows event logs and nothing else, so the Linux rules are
// executed by Zircolite against a corpus of auditd records. Neither reads Zeek,
// so the network rules are executed by rastro itself, which makes those
// manifests a check of the engine against the evidence and not against an
// independent implementation — weaker, and every such manifest says so. Each
// manifest names the engine it needs; everything after that — the per-sample
// counts, the repository-wide total, the negative control — works the same
// either way.
//
// Two things are asserted for every rule:
//
//   - each listed sample produces the stated number of hits, and
//   - the repository-wide total for the rule matches.
//
// The second one is what catches a broken exclusion filter, which shows up as
// MORE hits rather than fewer and would pass a positive-only test.
package ruletest

import (
	"encoding/csv"
	"encoding/json"
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

// Engine names, as written in the manifests. A manifest with no engine field
// means hayabusa, so the Windows manifests did not have to be touched when the
// second engine arrived.
const (
	engineHayabusa  = "hayabusa"
	engineZircolite = "zircolite"
	engineRastro    = "rastro"
)

// Where each engine's rules and evidence live. Keeping the two corpora apart
// matters: the Linux samples are fetched file by file rather than cloned, and
// mixing them into datasets/ would make it impossible to tell which pinned
// source a sample came from.
var engineLayout = map[string]struct {
	rules    string
	datasets string
}{
	engineHayabusa:  {rules: filepath.Join("rules", "windows"), datasets: "datasets"},
	engineZircolite: {rules: filepath.Join("rules", "linux"), datasets: "datasets-linux"},
	engineRastro:    {rules: filepath.Join("rules", "network"), datasets: "datasets-compound"},
}

// manifest mirrors the YAML files under tests/.
type manifest struct {
	name   string // file name, for error messages
	Rule   string `yaml:"rule"`
	RuleID string `yaml:"rule_id"`

	// Engine selects the runner. Empty means hayabusa.
	Engine string `yaml:"engine"`

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

func (m manifest) engine() string {
	if m.Engine == "" {
		return engineHayabusa
	}
	return m.Engine
}

// detection is one match, reduced to the two fields the assertions need: which
// rule fired and which sample file it fired on.
type detection struct {
	ruleID string
	file   string // path relative to that engine's dataset root, forward slashes
}

func TestRulesMatchTheirManifests(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("cannot locate repository root: %v", err)
	}

	if err := assertRulesAreSorted(root); err != nil {
		t.Fatal(err)
	}

	manifests, err := loadManifests(filepath.Join(root, "tests"))
	if err != nil {
		t.Fatalf("cannot read manifests: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("no manifests found under tests/")
	}

	// Each engine is started once, and only if some manifest asks for it. A
	// contributor working on Windows rules alone should not need the Linux
	// corpus on disk to run the suite.
	detections := map[string][]detection{}
	for _, name := range enginesUsedBy(manifests) {
		found, ok := runEngine(t, root, name)
		if !ok {
			continue // runEngine already skipped or failed
		}
		detections[name] = found
	}

	for _, m := range manifests {
		t.Run(m.name, func(t *testing.T) {
			found, ran := detections[m.engine()]
			if !ran {
				t.Skipf("%s is not available", m.engine())
			}

			// Count this rule's hits, grouped by the file they came from.
			perFile := map[string]int{}
			total := 0
			for _, d := range found {
				if d.ruleID != m.RuleID {
					continue
				}
				perFile[d.file]++
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
				assertNegativeControl(t, root, m)
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

// assertRulesAreSorted refuses a rule left directly under rules/. Each engine is
// pointed at its own subdirectory, so a rule in neither would never be executed
// by anything and its manifest would fail with a confusing zero.
func assertRulesAreSorted(root string) error {
	stray, err := filepath.Glob(filepath.Join(root, "rules", "*.yml"))
	if err != nil {
		return err
	}
	if len(stray) == 0 {
		return nil
	}
	var names []string
	for _, p := range stray {
		names = append(names, filepath.Base(p))
	}
	return fmt.Errorf("rule(s) sitting directly in rules/: %s\n"+
		"  every rule belongs in rules/windows/, rules/linux/ or rules/network/, because that is how\n"+
		"  the suite decides which engine runs it. A rule left here is never executed",
		strings.Join(names, ", "))
}

func enginesUsedBy(manifests []manifest) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range manifests {
		if !seen[m.engine()] {
			seen[m.engine()] = true
			out = append(out, m.engine())
		}
	}
	return out
}

// runEngine locates the tools and the evidence one engine needs, runs it over
// every rule of its kind, and returns the detections. The bool reports whether
// the run happened at all.
func runEngine(t *testing.T, root, engine string) ([]detection, bool) {
	t.Helper()

	layout, known := engineLayout[engine]
	if !known {
		t.Fatalf("manifest asks for unknown engine %q", engine)
	}

	datasets := filepath.Join(root, layout.datasets)
	if !isDir(datasets) {
		skipOrFail(t, fmt.Sprintf("%s/ not found — see tests/README.md for how to fetch it", layout.datasets))
		return nil, false
	}

	rules := filepath.Join(root, layout.rules)
	found, err := runRules(t, engine, root, rules, datasets)
	if err != nil {
		if errors.Is(err, errToolMissing) {
			skipOrFail(t, fmt.Sprintf("%s not found: %v", engine, err))
			return nil, false
		}
		t.Fatalf("%s run failed: %v", engine, err)
	}
	return found, true
}

var errToolMissing = errors.New("tool not found")

func runRules(t *testing.T, engine, root, rules, datasets string) ([]detection, error) {
	switch engine {
	case engineHayabusa:
		bin, err := findHayabusa(root)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errToolMissing, err)
		}
		return runHayabusa(t, bin, rules, datasets)
	case engineZircolite:
		cmd, err := findZircolite(root)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errToolMissing, err)
		}
		return runZircolite(t, cmd, rules, datasets)
	case engineRastro:
		return runRastro(t, root, rules, datasets)
	}
	return nil, fmt.Errorf("unknown engine %q", engine)
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
			file:   relativeToDataset(row[evtxCol], datasets),
		})
	}
	return out2, nil
}

// zircoliteResult is one entry of Zircolite's JSON output. It emits one entry
// per rule and input file, each carrying the events that matched.
type zircoliteResult struct {
	ID      string `json:"id"`
	Matches []struct {
		OriginalLogfile string `json:"OriginalLogfile"`
	} `json:"matches"`
}

// runZircolite executes the Linux rules over the auditd corpus. The tool is
// started from a temporary working directory on purpose: it drops a log file
// beside wherever it runs, and the repository is not the place for it.
func runZircolite(t *testing.T, command []string, rules, datasets string) ([]detection, error) {
	t.Helper()

	work := t.TempDir()
	out := filepath.Join(work, "detections.json")

	args := append(append([]string{}, command[1:]...),
		"-e", datasets,
		"-AU", // the corpus is auditd text, not Windows event logs
		"-r", rules,
		"-o", out,
		"-l", filepath.Join(work, "zircolite.log"),
		"-q",
	)
	cmd := exec.Command(command[0], args...)
	cmd.Dir = work
	if combined, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(string(combined), 800))
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var results []zircoliteResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil, fmt.Errorf("parsing zircolite output: %w", err)
	}

	// Zircolite reports the source as a bare file name rather than a path. The
	// Linux corpus is kept flat for exactly this reason, so the name is the key
	// the manifests use.
	var out2 []detection
	for _, r := range results {
		for _, m := range r.Matches {
			out2 = append(out2, detection{ruleID: r.ID, file: m.OriginalLogfile})
		}
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
		if _, known := engineLayout[m.engine()]; !known {
			return nil, fmt.Errorf("%s: unknown engine %q", filepath.Base(p), m.Engine)
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

// findZircolite returns the command that runs it. There is no released binary,
// and installing the package alone is not enough: Zircolite reads its field
// mapping from a config directory that ships with the repository, so the
// repository is what lives under tools/ and the script there is what gets run.
// It resolves that config relative to its own path, which is why the test can
// start it from a temporary working directory and keep its log out of the way.
func findZircolite(root string) ([]string, error) {
	script := os.Getenv("ZIRCOLITE")
	if script == "" {
		script = filepath.Join(root, "tools", "zircolite", "zircolite.py")
	}
	if !fileExists(script) {
		return nil, fmt.Errorf("no zircolite.py at %s and ZIRCOLITE is unset", script)
	}
	// Each candidate is asked to import the package before it is trusted. On
	// Windows a python3 that cannot is usually the Microsoft Store stub rather
	// than a real interpreter, and on any machine it means the dependencies were
	// never installed — both of which are clearer to report here than as a
	// confusing failure once the engine is already running.
	var tried []string
	for _, name := range []string{"python3", "python"} {
		bin, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		tried = append(tried, bin)
		if err := exec.Command(bin, "-c", "import zircolite").Run(); err == nil {
			return []string{bin, script}, nil
		}
	}
	if len(tried) == 0 {
		return nil, errors.New("no python interpreter on PATH")
	}
	return nil, fmt.Errorf("none of %v can import zircolite; install it with: pip install ./tools/zircolite", tried)
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
func assertNegativeControl(t *testing.T, root string, m manifest) {
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

	detectionNode := mappingValue(doc.Content[0], "detection")
	if detectionNode == nil {
		t.Errorf("negative control: rule has no detection block")
		return
	}

	neutralised := 0
	// A mapping node stores keys and values as alternating children.
	for i := 0; i+1 < len(detectionNode.Content); i += 2 {
		key := detectionNode.Content[i].Value
		if !strings.HasPrefix(key, "filter") {
			continue
		}
		blankOut(detectionNode.Content[i+1])
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

	layout := engineLayout[m.engine()]
	found, err := runRules(t, m.engine(), root, dir, filepath.Join(root, layout.datasets))
	if err != nil {
		t.Errorf("negative control: %s run failed: %v", m.engine(), err)
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

// runRastro executes the rules with this repository's own engine, through the
// binary and its JSON report rather than by calling the packages. The JSON is
// the contract a SIEM ingests, and the binary is the one path both commands
// share; a test that rebuilt the pipeline out of the packages would be testing
// a third path nobody runs.
//
// It is built from the tree under test every time. An old rastro.exe lying in
// the repository has already been run against new code twice, and the output
// looked like a bug in the code both times.
//
// One run over the whole corpus, as Hayabusa and Zircolite do. The join between
// host and network then spans campaigns, which can turn an attribution into an
// ambiguity where two campaigns share an address; it cannot change which
// records a rule matches, and hits are all a manifest counts.
func runRastro(t *testing.T, root, rules, datasets string) ([]detection, error) {
	t.Helper()

	gobin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errToolMissing, err)
	}
	work := t.TempDir()
	bin := filepath.Join(work, "rastro")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command(gobin, "build", "-o", bin, "./cmd/rastro")
	build.Dir = root
	if combined, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("building rastro: %w: %s", err, truncate(string(combined), 800))
	}

	// datasets-compound is a directory of real files, but a corpus is often a
	// link to where the evidence lives, and WalkDir does not follow one.
	// rastro resolves its own argument; this only keeps the error readable.
	out := filepath.Join(work, "report.json")
	cmd := exec.Command(bin, "report", "-rules", rules, "-format", "json", "-out", out, datasets)
	if combined, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, truncate(string(combined), 800))
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	var rep struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
			Origin struct {
				File string `json:"file"`
			} `json:"origin"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("parsing rastro's report: %w", err)
	}
	var found []detection
	for _, f := range rep.Findings {
		// A finding with no rule id would be counted against no manifest and
		// vanish from the totals, which is the silence this suite exists for.
		if f.RuleID == "" || f.Origin.File == "" {
			return nil, fmt.Errorf("a finding in rastro's report has no rule id or no origin file: %+v", f)
		}
		found = append(found, detection{ruleID: f.RuleID, file: filepath.ToSlash(f.Origin.File)})
	}
	return found, nil
}

// Every rule of this repository is executed by some engine and checked by a
// manifest.
//
// This is the hole the network rule fell into the day it was written. Nothing
// required a rule to have a manifest: the suite iterates manifests, so a rule
// without one was never run by anything, never counted, and never failed. And a
// rule in a directory no engine is pointed at was the same thing one level up.
// assertRulesAreSorted catches a rule left directly under rules/; this catches
// the rest.
func TestEveryRuleHasAManifest(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("cannot locate repository root: %v", err)
	}
	manifests, err := loadManifests(filepath.Join(root, "tests"))
	if err != nil {
		t.Fatalf("cannot read manifests: %v", err)
	}
	byPath := map[string][]manifest{}
	for _, m := range manifests {
		byPath[filepath.ToSlash(m.Rule)] = append(byPath[filepath.ToSlash(m.Rule)], m)
	}
	engineFor := map[string]string{}
	for name, l := range engineLayout {
		engineFor[filepath.ToSlash(l.rules)] = name
	}

	var rules []string
	err = filepath.WalkDir(filepath.Join(root, "rules"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yml", ".yaml":
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rules = append(rules, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules under rules/")
	}

	for _, rel := range rules {
		dir := rel[:strings.LastIndex(rel, "/")]
		engine, executed := engineFor[dir]
		if !executed {
			t.Errorf("%s: no engine runs rules in %s/, so this rule is never executed", rel, dir)
			continue
		}

		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		var head struct {
			ID string `yaml:"id"`
		}
		if err := yaml.Unmarshal(raw, &head); err != nil || head.ID == "" {
			t.Errorf("%s: no readable id; a manifest is matched to its rule by id", rel)
			continue
		}

		ms := byPath[rel]
		switch {
		case len(ms) == 0:
			t.Errorf("%s: no manifest under tests/ names it, so nothing checks what it matches", rel)
		case len(ms) > 1:
			t.Errorf("%s: %d manifests name it; the totals would be asserted twice and could disagree", rel, len(ms))
		case ms[0].RuleID != head.ID:
			t.Errorf("%s: its manifest expects id %s and the rule has %s; every hit would be counted against nothing",
				rel, ms[0].RuleID, head.ID)
		case ms[0].engine() != engine:
			t.Errorf("%s: its manifest asks for %s, and rules in %s/ are run by %s",
				rel, ms[0].engine(), dir, engine)
		}
	}
}
