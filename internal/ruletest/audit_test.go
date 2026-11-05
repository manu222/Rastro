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
	"github.com/manu222/rastro/internal/source/auditd"
	"github.com/manu222/rastro/internal/source/evtx"
)

// This file is the audit: it reads the whole pinned corpus and asserts the two
// properties that keep the pipeline honest.
//
// The first is that every record is read. Not most of them, not enough of them:
// all of them. Three times during this project a change made records
// unreadable in bulk — a type switch that did not match a named integer, a
// security descriptor arriving as bytes, a field holding a list — and each time
// the output was a confident number with nothing in it to say what was missing.
// A test that fails on the first unreadable record is what turns that into a
// build failure instead of a discovery weeks later.
//
// The second is narrower and more interesting. The corpus contains providers
// nobody has described, and describing all of them would be weeks of work for
// events no rule touches, so an empty gap list is not the bar. The bar is that
// a provider WITH a table must have a complete one: a field of Sysmon or of the
// Security channel arriving in a shape the table does not cover means the
// description is wrong, and a rule written against that field is matching
// something other than what its author believed.

func TestTheCorpusIsReadCompletely(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("cannot locate repository root: %v", err)
	}

	t.Run("windows", func(t *testing.T) {
		evidence := corpusPath(t, root, "datasets")
		reader := evtx.New(evidence)

		var files, records, unreadable, damaged, skipped, unlabelled int
		var firstFailure error
		walk(t, evidence, ".evtx", func(path string) {
			files++
			stats, err := reader.ReadFile(path, func(e *event.Event) error {
				records++
				if e.Origin.Product == "" {
					unlabelled++
				}
				return nil
			})
			if err != nil {
				t.Errorf("%s: %v", filepath.Base(path), err)
				return
			}
			unreadable += stats.Unreadable
			damaged += stats.DamagedChunks
			skipped += stats.SkippedFields
			if stats.FirstFailure != nil && firstFailure == nil {
				firstFailure = fmt.Errorf("%s: %w", filepath.Base(path), stats.FirstFailure)
			}
		})

		t.Logf("%d file(s), %d record(s)", files, records)
		if records == 0 {
			t.Fatal("the corpus is present and no records were read from it")
		}
		if unreadable > 0 {
			t.Errorf("%d record(s) could not be read; first cause: %v", unreadable, firstFailure)
		}
		if damaged > 0 {
			// Not a failure in itself — evidence arrives broken and skipping a
			// damaged chunk is the right behaviour — but a change in the count
			// means the corpus or the parser moved, and either is worth
			// knowing about.
			t.Logf("%d damaged chunk(s) were skipped", damaged)
		}
		if skipped > 0 {
			t.Errorf("%d field(s) could not be rendered and were dropped from their records", skipped)
		}
		// Every reader has to say what kind of evidence it produced, because a
		// rule that states a logsource will not match a record that states
		// none. A reader that forgets would silently stop most of the public
		// corpus from ever firing, and the only sign of it would be a smaller
		// number of findings than there should be.
		if unlabelled > 0 {
			t.Errorf("%d record(s) carry no product label, so no rule with a logsource can match them", unlabelled)
		}

		// The audit proper.
		var undescribed []string
		for _, gap := range reader.Gaps() {
			if reader.Normaliser.Declares(gap.Producer) {
				t.Errorf("%s declares a table and %s arrived as %s anyway (declared %s, e.g. %s): "+
					"the table is wrong, and a rule written against that field is matching "+
					"something other than what its author believed",
					gap.Producer, gap.Field, gap.Shape, gap.Declared, gap.Sample)
				continue
			}
			undescribed = append(undescribed, gap.Producer+"."+gap.Field+" ("+gap.Shape+")")
		}
		if len(undescribed) > 0 {
			sort.Strings(undescribed)
			// Listed and not failed: these are providers nobody has described,
			// which is a known absence rather than a broken description. The
			// list is in the report of every analysis for the same reason.
			t.Logf("%d field(s) of providers with no table, which is a known gap:\n  %s",
				len(undescribed), strings.Join(undescribed, "\n  "))
		}
	})

	t.Run("linux", func(t *testing.T) {
		evidence := corpusPath(t, root, "datasets-linux")
		reader := auditd.New(evidence)

		var files, records, unparsed, unlabelled int
		var firstFailure error
		walk(t, evidence, ".log", func(path string) {
			files++
			stats, err := reader.ReadFile(path, func(e *event.Event) error {
				records++
				if e.Origin.Product == "" || e.Origin.Service == "" {
					unlabelled++
				}
				return nil
			})
			if err != nil {
				t.Errorf("%s: %v", filepath.Base(path), err)
				return
			}
			unparsed += stats.Unparsed
			if stats.FirstFailure != nil && firstFailure == nil {
				firstFailure = fmt.Errorf("%s: %w", filepath.Base(path), stats.FirstFailure)
			}
		})

		t.Logf("%d file(s), %d record(s)", files, records)
		if records == 0 {
			t.Fatal("the corpus is present and no records were read from it")
		}
		if unparsed > 0 {
			// Every line of this corpus is an audit record. A line that is not
			// means either the corpus changed or the parser stopped
			// understanding a style it used to.
			t.Errorf("%d line(s) were not read as audit records; first: %v", unparsed, firstFailure)
		}
		if unlabelled > 0 {
			t.Errorf("%d record(s) carry no evidence label", unlabelled)
		}
	})
}

// corpusPath resolves an evidence directory, or says why there is none.
func corpusPath(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if _, err := os.Stat(path); err != nil {
		skipOrFail(t, fmt.Sprintf("the %s corpus is not on this machine (see tests/README.md)", name))
	}
	// A corpus is often a link to wherever the evidence actually lives, and
	// WalkDir does not follow one, not even its own root, and reports no error
	// when the root is one.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return path
}

func walk(t *testing.T, root, ext string, visit func(path string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ext) {
			return nil
		}
		visit(path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
