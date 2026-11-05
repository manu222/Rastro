package sigma

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The coverage of this loader against the public rule corpus is a number in the
// README, so it is measured here rather than claimed. The test is skipped when
// the corpus is not on the machine — the same way the Zircolite tests skip when
// that tool is not installed — so a clone of this repository still builds and
// tests without downloading four thousand rules.
//
// To run it:
//
//	git clone --depth 1 https://github.com/SigmaHQ/sigma tools/sigmahq
//	go test ./internal/sigma/ -run Corpus -v
//
// or point RASTRO_SIGMA_CORPUS at a clone somewhere else.
//
// The threshold is deliberately below the number the loader currently reaches.
// It is there to catch a regression, not to be a trophy: a change that drops
// coverage by a point should fail, and the measured figure is printed either
// way so that the README can be corrected rather than trusted.
const minimumCoverage = 0.99

func corpusDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("RASTRO_SIGMA_CORPUS"); dir != "" {
		return dir
	}
	root, err := repoRoot()
	if err != nil {
		t.Skipf("cannot find the repository root: %v", err)
	}
	dir := filepath.Join(root, "tools", "sigmahq")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("the SigmaHQ corpus is not on this machine; clone it into tools/sigmahq to measure coverage")
	}
	return dir
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func TestCorpusCoverage(t *testing.T) {
	root := corpusDir(t)

	// Only the directories that hold rules meant to be used. The deprecated and
	// unsupported folders are there to record what SigmaHQ removed, the tests
	// and documentation folders describe the format, and counting any of them
	// would flatter or punish the figure for no reason.
	dirs := []string{
		"rules", "rules-emerging-threats", "rules-threat-hunting",
		"rules-dfir", "rules-compliance", "rules-placeholder",
	}

	var total, loaded int
	byFeature := map[string]int{}
	examples := map[string]*Unsupported{}

	for _, d := range dirs {
		path := filepath.Join(root, d)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		res, err := LoadDir(path)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		loaded += len(res.Rules)
		total += len(res.Rules) + len(res.Refused)
		for _, u := range res.Refused {
			byFeature[u.Feature]++
			if examples[u.Feature] == nil {
				examples[u.Feature] = u
			}
		}
	}

	if total == 0 {
		t.Skip("no rules found in the corpus")
	}

	coverage := float64(loaded) / float64(total)
	t.Logf("loaded %d of %d rules (%.1f%%)", loaded, total, coverage*100)

	features := make([]string, 0, len(byFeature))
	for f := range byFeature {
		features = append(features, f)
	}
	sort.Slice(features, func(i, j int) bool { return byFeature[features[i]] > byFeature[features[j]] })
	for _, f := range features {
		t.Logf("  refused %5d  %-14s e.g. %s", byFeature[f], f, examples[f])
	}

	if coverage < minimumCoverage {
		t.Errorf("coverage fell to %.1f%%, below the %.0f%% this loader is supposed to reach",
			coverage*100, minimumCoverage*100)
	}
}

// Every rule that loads has to be usable: a condition whose names all resolve,
// and selections that actually hold matchers. A rule that loads into something
// empty would match nothing while reporting itself as covered, which is worse
// than being refused.
func TestEveryLoadedCorpusRuleIsUsable(t *testing.T) {
	root := corpusDir(t)
	res, err := LoadDir(filepath.Join(root, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Skip("no rules loaded")
	}

	for _, c := range res.Rules {
		if c.Condition == nil {
			t.Fatalf("%s: loaded with no condition", c.Rule.Title)
		}
		for _, name := range c.Condition.Names() {
			if _, ok := c.Selections[name]; !ok {
				t.Fatalf("%s: condition names %q and the selection is not there", c.Rule.Title, name)
			}
		}
		for name, sel := range c.Selections {
			if len(sel) == 0 {
				t.Fatalf("%s: selection %s compiled to nothing", c.Rule.Title, name)
			}
			for _, set := range sel {
				if len(set) == 0 {
					t.Fatalf("%s: selection %s has an empty field set", c.Rule.Title, name)
				}
				for _, test := range set {
					if len(test.Values) == 0 && !test.Null && test.Ref == "" {
						t.Fatalf("%s: %s.%s has nothing to match against",
							c.Rule.Title, name, test.Field)
					}
				}
			}
		}
	}
	t.Logf("%d rules loaded and all of them have something to match on", len(res.Rules))
}
