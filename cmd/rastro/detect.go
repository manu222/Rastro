package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
	"github.com/manu222/rastro/internal/source/evtx"
)

// detect reads a directory of evidence, runs a directory of rules over it, and
// says what fired and why.
//
// It is the first thing in this repository that does the job the tool exists
// for, and it prints three things rather than one. What fired is the obvious
// part. What was refused matters just as much, because a rule that did not load
// is coverage the analysis does not have and the analyst has to know that. And
// the reason behind each finding is the part that makes a report worth reading:
// "rule 1 fired" is not something anybody can act on.
func detect(rulesDir, evidenceDir string, examples int) error {
	loaded, err := sigma.LoadDir(rulesDir)
	if err != nil {
		return err
	}
	if len(loaded.Rules) == 0 {
		return fmt.Errorf("no rules loaded from %s", rulesDir)
	}

	fmt.Printf("Rules loaded    : %d\n", len(loaded.Rules))
	if len(loaded.Refused) > 0 {
		fmt.Printf("Rules refused   : %d  (these are blind spots, not warnings)\n", len(loaded.Refused))
		byFeature := loaded.ByFeature()
		causes := make([]string, 0, len(byFeature))
		for cause := range byFeature {
			causes = append(causes, cause)
		}
		sort.Strings(causes)
		for _, cause := range causes {
			fmt.Printf("  %-14s %d\n", cause, byFeature[cause])
		}
		for _, u := range loaded.Refused {
			fmt.Printf("  - %v\n", u)
		}
	}

	// Rules are grouped by the event identifiers they can possibly match, so
	// that a record only meets the rules that have a chance. The grouping is
	// derived from the rules themselves — a selection comparing EventID to a
	// fixed value — and a rule that names no identifier is checked against
	// everything, which is the safe side of the trade.
	index := newRuleIndex(loaded.Rules)

	root, err := evidenceRoot(evidenceDir)
	if err != nil {
		return err
	}
	reader := evtx.New(root)
	type finding struct {
		rule  string
		level string
		event *event.Event
		hits  []sigma.Hit
	}

	var (
		records   int
		files     int
		evaluated int64
		byRule    = map[string]int{}
		levels    = map[string]int{}
		kept      []finding
	)

	start := time.Now()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".evtx") {
			return nil
		}
		files++
		_, rerr := reader.ReadFile(path, func(e *event.Event) error {
			records++
			candidates := index.forEvent(e)
			evaluated += int64(len(candidates))
			for _, c := range candidates {
				if !c.Matches(e.Raw) {
					continue
				}
				byRule[c.Rule.Title]++
				levels[c.Rule.Level]++
				if len(kept) < examples {
					kept = append(kept, finding{
						rule:  c.Rule.Title,
						level: c.Rule.Level,
						event: e,
						hits:  c.Explain(e.Raw),
					})
				}
			}
			return nil
		})
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), rerr)
		}
		return nil
	})
	if err != nil {
		return err
	}

	elapsed := time.Since(start)
	fmt.Printf("\nFiles read      : %d\n", files)
	fmt.Printf("Records         : %d\n", records)
	fmt.Printf("Evaluations     : %d  (%.1f rules per record on average)\n",
		evaluated, float64(evaluated)/float64(max(records, 1)))
	fmt.Printf("Elapsed         : %s\n", elapsed.Round(time.Millisecond))
	if records > 0 {
		fmt.Printf("Per record      : %s\n", (elapsed / time.Duration(records)).Round(time.Nanosecond))
	}

	total := 0
	for _, n := range byRule {
		total += n
	}
	fmt.Printf("\nFindings        : %d\n", total)
	titles := make([]string, 0, len(byRule))
	for title := range byRule {
		titles = append(titles, title)
	}
	sort.Slice(titles, func(i, j int) bool {
		if byRule[titles[i]] != byRule[titles[j]] {
			return byRule[titles[i]] > byRule[titles[j]]
		}
		return titles[i] < titles[j]
	})
	for _, title := range titles {
		fmt.Printf("  %-62s %5d\n", title, byRule[title])
	}

	// Rules that loaded and never fired. Over a corpus chosen to exercise them
	// that is worth knowing: it is either a rule with nothing to find here, or
	// a rule that cannot find anything anywhere.
	var silent []string
	for _, c := range loaded.Rules {
		if byRule[c.Rule.Title] == 0 {
			silent = append(silent, c.Rule.Title)
		}
	}
	if len(silent) > 0 {
		sort.Strings(silent)
		fmt.Printf("\nLoaded but silent: %d\n", len(silent))
		for _, title := range silent {
			fmt.Printf("  %s\n", title)
		}
	}

	if len(kept) > 0 {
		fmt.Printf("\nWhy the first %d fired:\n", len(kept))
		for _, f := range kept {
			fmt.Printf("\n  [%s] %s\n", strings.ToUpper(f.level), f.rule)
			fmt.Printf("    %s  %s  record %d of %s\n",
				f.event.Time.Format("2006-01-02 15:04:05"), f.event.Host.Value,
				f.event.Origin.Record, f.event.Origin.Path)
			if f.event.Action != "" {
				fmt.Printf("    %s", f.event.Action)
				if f.event.User.Known() {
					fmt.Printf(" by %s", f.event.User.Value)
				}
				fmt.Println()
			}
			for _, h := range f.hits {
				fmt.Printf("    because %s = %s  (rule asked for %s)\n",
					h.Field, truncate(h.Value, 80), h.Pattern)
			}
		}
	}
	return nil
}

// evidenceRoot resolves the directory an analysis was pointed at.
//
// filepath.WalkDir does not follow a symbolic link, including the one it is
// handed as its root, and it reports no error when the root is one: it walks
// nothing and returns nil. Evidence lives on mounted shares and in linked case
// folders, so a tool that answers "0 records read" because the path was a link
// is exactly the silent zero this project exists to avoid. The link is
// resolved, and a root that is not a directory is said out loud.
func evidenceRoot(dir string) (string, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("%s: %w", dir, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return resolved, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ruleIndex sorts rules by the event identifier they can match.
//
// Without it every record meets every rule, which over a million records and
// the public corpus is four billion evaluations. The measurement that justifies
// it is in internal/sigma: one rule against one record costs about 200ns, so
// four billion of them is a day of work to answer a question that mostly has an
// obvious no.
//
// The derivation is deliberately timid. A rule is filed under an identifier
// only when one of its selections compares EventID to a fixed value and that
// selection is required for the rule to fire. Anything else — a rule with no
// identifier, an identifier behind an or, an identifier tested with a wildcard
// — goes in the list that is checked against every record. A wrong guess here
// would silently stop a rule from ever being asked, which is the one failure
// this engine is built to avoid, so the index only ever narrows when it is
// certain.
type ruleIndex struct {
	byID    map[string][]*sigma.Compiled
	always  []*sigma.Compiled
	scratch []*sigma.Compiled
}

func newRuleIndex(rules []*sigma.Compiled) *ruleIndex {
	idx := &ruleIndex{byID: map[string][]*sigma.Compiled{}}
	for _, c := range rules {
		ids := requiredEventIDs(c)
		if len(ids) == 0 {
			idx.always = append(idx.always, c)
			continue
		}
		for _, id := range ids {
			idx.byID[id] = append(idx.byID[id], c)
		}
	}
	return idx
}

// forEvent returns the rules worth asking about one record. The slice is reused
// between calls, because this is the hot path and the caller never keeps it.
func (idx *ruleIndex) forEvent(e *event.Event) []*sigma.Compiled {
	idx.scratch = idx.scratch[:0]
	idx.scratch = append(idx.scratch, idx.always...)
	if id := e.Raw["EventID"]; id != "" {
		idx.scratch = append(idx.scratch, idx.byID[id]...)
	}
	return idx.scratch
}

// requiredEventIDs reads the identifiers a rule cannot fire without.
//
// It walks only the top-level conjunction of the condition: selections joined
// by and, which every rule in this repository and most of the public corpus
// use. A selection under an or or a not says nothing about what the rule
// requires, so it is ignored, and the rule then ends up in the always list.
func requiredEventIDs(c *sigma.Compiled) []string {
	var ids []string
	for _, name := range requiredSelections(c.Condition) {
		for _, set := range c.Selections[name] {
			// Every shape of the selection has to pin the identifier, or the
			// rule can fire on a record with a different one.
			found := false
			for _, test := range set {
				if !strings.EqualFold(test.Field, "EventID") || test.Null || test.Ref != "" {
					continue
				}
				for _, m := range test.Values {
					exact, ok := m.(sigma.Exact)
					if !ok {
						// Anything less definite than one value — a wildcard,
						// a regular expression — and the rule keeps its place
						// in the list that sees every record.
						return nil
					}
					ids = append(ids, exact.Exact())
					found = true
				}
			}
			if !found {
				return nil
			}
		}
	}
	return ids
}

// requiredSelections lists the selections joined by and at the top of a
// condition, which are the ones that have to match.
func requiredSelections(e sigma.Expr) []string {
	switch node := e.(type) {
	case sigma.Ref:
		return []string{node.Name}
	case sigma.And:
		return append(requiredSelections(node.Left), requiredSelections(node.Right)...)
	default:
		return nil
	}
}

// runDetect parses the arguments of the detect command.
func runDetect(args []string) error {
	rulesDir := "rules"
	examples := 5
	for len(args) > 1 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-rules":
			rulesDir = args[1]
			args = args[2:]
		case "-examples":
			n, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("-examples wants a number, got %q", args[1])
			}
			examples = n
			args = args[2:]
		default:
			return fmt.Errorf("unknown option %s", args[0])
		}
	}
	if len(args) != 1 {
		return fmt.Errorf("detect wants one evidence directory")
	}
	return detect(rulesDir, args[0], examples)
}
