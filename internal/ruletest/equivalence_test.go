package ruletest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
	"github.com/manu222/rastro/internal/source/evtx"
)

// This file checks Rastro's own rule engine against the engine the manifests
// were built with.
//
// The manifests under tests/ record what Hayabusa found: which rule fired, in
// which sample file, how many times. That makes them an oracle. An engine
// written from scratch has exactly one way to be trusted, and it is not that
// its author read the specification carefully — it is that it agrees, rule by
// rule and file by file, with an implementation nobody involved here wrote.
//
// The comparison is per file and not per total on purpose. A rule that fires
// the right number of times in the wrong places is wrong, and a total would
// hide it.
//
// Hayabusa is not run here. It was run when the manifests were written, by
// TestRulesMatchTheirManifests in this same package, which is what keeps the
// expectations honest; this test reads what that one proved.

func TestOwnEngineAgreesWithTheReferenceEngine(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("cannot locate repository root: %v", err)
	}

	evidence := filepath.Join(root, "datasets")
	if _, err := os.Stat(evidence); err != nil {
		t.Skip("the Windows corpus is not on this machine; see tests/README.md")
	}

	manifests, err := loadManifests(filepath.Join(root, "tests"))
	if err != nil {
		t.Fatalf("cannot read manifests: %v", err)
	}

	// Only the manifests whose expectations came from a Windows engine. The
	// Linux rules are auditd and there is no reader for that evidence yet, so
	// comparing them here would be comparing against nothing.
	type expectation struct {
		manifest manifest
		rule     *sigma.Compiled
	}
	var expectations []expectation
	for _, m := range manifests {
		if m.engine() != engineHayabusa {
			continue
		}
		c, err := sigma.LoadFile(filepath.Join(root, m.Rule))
		if err != nil {
			t.Errorf("%s: the rule its manifest points at does not load: %v", m.name, err)
			continue
		}
		expectations = append(expectations, expectation{manifest: m, rule: c})
	}
	if len(expectations) == 0 {
		t.Fatal("no Windows manifests found")
	}

	// Count the hits of every rule in every file, with this engine.
	got := map[string]map[string]int{} // rule path -> file -> hits
	for _, e := range expectations {
		got[e.manifest.Rule] = map[string]int{}
	}

	reader := evtx.New(evidence)
	records := 0
	err = filepath.WalkDir(evidence, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".evtx") {
			return nil
		}
		rel, err := filepath.Rel(evidence, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		_, rerr := reader.ReadFile(path, func(ev *event.Event) error {
			records++
			for _, e := range expectations {
				if e.rule.Matches(ev.Raw) {
					got[e.manifest.Rule][rel]++
				}
			}
			return nil
		})
		if rerr != nil {
			t.Errorf("%s: %v", rel, rerr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if records == 0 {
		// The evidence is there and nothing came out of it. Skipping would turn
		// a broken reader into a quiet pass, which is the one thing this
		// repository does not do.
		t.Fatal("the corpus is present and no records were read from it")
	}
	t.Logf("%d records read", records)

	// Compare, file by file.
	for _, e := range expectations {
		mine := got[e.manifest.Rule]
		theirs := map[string]int{}
		for _, exp := range e.manifest.Expect {
			theirs[filepath.ToSlash(exp.File)] += exp.Hits
		}

		for file, want := range theirs {
			if have := mine[file]; have != want {
				t.Errorf("%s in %s: the reference engine found %d, this one found %d",
					shortRule(e.manifest.Rule), file, want, have)
			}
		}
		// A hit in a file the manifest says nothing about is a disagreement
		// too, and the more interesting direction: it is this engine firing
		// where the reference one did not.
		for file, have := range mine {
			if _, expected := theirs[file]; !expected && have > 0 {
				t.Errorf("%s fired %d time(s) in %s, which its manifest does not list",
					shortRule(e.manifest.Rule), have, file)
			}
		}
	}

	// And the totals, printed rather than asserted: the per-file comparison
	// above is stricter, and the summary is what a person reads.
	var lines []string
	for _, e := range expectations {
		total := 0
		for _, n := range got[e.manifest.Rule] {
			total += n
		}
		lines = append(lines, fmt.Sprintf("  %-56s %3d", shortRule(e.manifest.Rule), total))
	}
	sort.Strings(lines)
	t.Logf("hits per rule, this engine:\n%s", strings.Join(lines, "\n"))
}

func shortRule(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".yml")
}
