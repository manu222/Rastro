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
	"github.com/manu222/rastro/internal/source/auditd"
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
	// Both halves, each against the engine its manifests came from: Hayabusa
	// for the Windows rules and EVTX, Zircolite for the Linux rules and
	// auditd. Two readers, two corpora, one comparison.
	t.Run("windows", func(t *testing.T) {
		compareAgainstManifests(t, engineHayabusa, "datasets", readEVTX)
	})
	t.Run("linux", func(t *testing.T) {
		compareAgainstManifests(t, engineZircolite, "datasets-linux", readAuditd)
	})
}

// readRecords reads one evidence file and hands every record to visit.
type readRecords func(t *testing.T, path string, visit func(*event.Event)) error

func readEVTX(t *testing.T, path string, visit func(*event.Event)) error {
	t.Helper()
	r := evtx.New(filepath.Dir(path))
	_, err := r.ReadFile(path, func(e *event.Event) error {
		visit(e)
		return nil
	})
	return err
}

func readAuditd(t *testing.T, path string, visit func(*event.Event)) error {
	t.Helper()
	r := auditd.New(filepath.Dir(path))
	stats, err := r.ReadFile(path, func(e *event.Event) error {
		visit(e)
		return nil
	})
	if stats.Unparsed > 0 {
		// Not a failure in itself: an audit log can carry lines from other
		// daemons. Reported so that a count of zero findings is never blamed
		// on the rules when it belongs to the parser.
		t.Logf("%s: %d line(s) were not audit records; first: %v",
			filepath.Base(path), stats.Unparsed, stats.FirstFailure)
	}
	return err
}

func compareAgainstManifests(t *testing.T, engine, corpus string, read readRecords) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("cannot locate repository root: %v", err)
	}

	evidence := filepath.Join(root, corpus)
	if _, err := os.Stat(evidence); err != nil {
		// A developer without the corpus sees a skip; CI, which fetches it at
		// a pinned commit, sees a failure. Otherwise a broken setup would
		// report success by running nothing at all.
		skipOrFail(t, fmt.Sprintf("the %s corpus is not on this machine (see tests/README.md)", corpus))
	}
	// A corpus is often a link to wherever the evidence actually lives, and
	// filepath.WalkDir does not follow a symbolic link - not even the one it is
	// given as its root, and it returns no error when the root is one. Without
	// this the test walked nothing and reported that the corpus was present and
	// empty, which is the same silent zero the reader itself guards against.
	if resolved, err := filepath.EvalSymlinks(evidence); err == nil {
		evidence = resolved
	}

	manifests, err := loadManifests(filepath.Join(root, "tests"))
	if err != nil {
		t.Fatalf("cannot read manifests: %v", err)
	}

	type expectation struct {
		manifest manifest
		rule     *sigma.Compiled
	}
	var expectations []expectation
	for _, m := range manifests {
		if m.engine() != engine {
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
		t.Fatalf("no manifests for %s", engine)
	}

	// Count the hits of every rule in every file, with this engine.
	got := map[string]map[string]int{} // rule path -> file -> hits
	for _, e := range expectations {
		got[e.manifest.Rule] = map[string]int{}
	}

	records := 0
	err = filepath.WalkDir(evidence, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return nil
		case strings.EqualFold(filepath.Ext(path), ".evtx"), strings.EqualFold(filepath.Ext(path), ".log"):
		default:
			return nil
		}
		rel, err := filepath.Rel(evidence, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		if rerr := read(t, path, func(ev *event.Event) {
			records++
			for _, e := range expectations {
				if e.rule.Matches(ev.Raw) {
					got[e.manifest.Rule][rel]++
				}
			}
		}); rerr != nil {
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
