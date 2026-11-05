package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/correlate"
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
	// Two passes over the evidence, and the reason is not laziness.
	//
	// The process creation that explains an event can be anywhere: a later
	// chunk of the same file, or another file entirely, because the directory
	// is walked in whatever order it gives and each file covers its own stretch
	// of time. A single pass would answer "who was behind this" with "nothing
	// yet" for any event whose creation had not been reached, which is a wrong
	// answer that depends on the order of a directory listing.
	//
	// Reading twice costs a second on this corpus at the measured 30µs per
	// record. The index built in the first pass holds only what can be an
	// ancestor — process creations and logon sessions, five hundred of 31,243
	// records here — so it does not grow with the size of the case.
	reader := evtx.New(root)
	lineage := correlate.New()
	if err := walkEvidence(root, reader, lineage.Observe); err != nil {
		return err
	}
	processes, logons := lineage.Size()
	fmt.Printf("Ancestors known : %d process creation(s), %d logon session(s)\n",
		processes, logons)

	type finding struct {
		rule        string
		level       string
		event       *event.Event
		hits        []sigma.Hit
		who         event.Field
		steps       []correlate.Step
		complete    bool
		escalations []correlate.Escalation
		entry       *correlate.Logon
		entryWho    event.Field
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
					f := finding{
						rule:  c.Rule.Title,
						level: c.Rule.Level,
						event: e,
						hits:  c.Explain(e.Raw),
						who:   lineage.Account(e),
					}
					f.steps, f.complete = lineage.Ancestry(e)
					f.escalations = correlate.Escalations(f.steps)
					f.entry, f.entryWho = lineage.Entry(f.steps)
					kept = append(kept, f)
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
				if f.who.Known() {
					fmt.Printf(" by %s", f.who.Value)
					if !f.who.Trusted() {
						// A deduced account is marked and its reasoning
						// printed. The alternative is a report whose reader
						// cannot tell what was recorded from what was worked
						// out, and that is not a forensic report.
						fmt.Printf(" (deduced: %s)", f.who.Why)
					}
				}
				fmt.Println()
			}
			for _, h := range f.hits {
				fmt.Printf("    because %s = %s  (rule asked for %s)\n",
					h.Field, truncate(h.Value, 80), h.Pattern)
			}
			printLineage(f.steps, f.complete)
			for _, esc := range f.escalations {
				fmt.Printf("    account changed from %s to %s at %s, record %d of %s\n",
					esc.FromUser, esc.ToUser, esc.To.Image, esc.To.Origin.Record, esc.To.Origin.Path)
			}
			if f.entry != nil {
				fmt.Printf("    came in through logon type %s", f.entry.Type)
				if f.entry.Address != "" && f.entry.Address != "-" {
					fmt.Printf(" from %s", f.entry.Address)
				}
				if f.entry.Workstation != "" && f.entry.Workstation != "-" {
					fmt.Printf(" (%s)", f.entry.Workstation)
				}
				fmt.Printf(" as %s, record %d of %s\n",
					f.entryWho.Value, f.entry.Origin.Record, f.entry.Origin.Path)
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

// walkEvidence reads every event log under root and hands each record to visit.
// Used for the pass that builds the ancestry index, where nothing is evaluated
// and nothing is counted.
func walkEvidence(root string, reader *evtx.Reader, visit func(*event.Event)) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".evtx") {
			return nil
		}
		_, rerr := reader.ReadFile(path, func(e *event.Event) error {
			visit(e)
			return nil
		})
		if rerr != nil {
			// A file that cannot be read is reported by the pass that counts;
			// here it only means fewer ancestors, and the lineages that depend
			// on it will say they are incomplete.
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), rerr)
		}
		return nil
	})
}

// printLineage shows the chain of processes above an event, oldest first,
// because that is the order the thing happened in.
func printLineage(steps []correlate.Step, complete bool) {
	if len(steps) == 0 {
		return
	}
	fmt.Println("    how it got there:")
	for i := len(steps) - 1; i >= 0; i-- {
		p := steps[i].Process
		indent := strings.Repeat("  ", len(steps)-1-i)
		fmt.Printf("      %s%s", indent, p.Image)
		if p.User != "" {
			fmt.Printf("   %s", p.User)
		}
		if p.Integrity != "" {
			fmt.Printf("   %s", p.Integrity)
		}
		fmt.Printf("   record %d of %s\n", p.Origin.Record, p.Origin.Path)
	}
	if !complete {
		// Said out loud, because a chain that stops because the evidence stops
		// is not a chain that reached the beginning.
		fmt.Println("      (the chain stops here: the parent's creation is not in this evidence)")
	}
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
// One required selection pinning the identifier is enough: if the rule cannot
// match without a selection that demands EventID be 1, then it cannot match a
// record whose EventID is 7, whatever the rest of the rule asks for. Demanding
// that every required selection pin it — which is what this did at first — left
// the index inert, because the selection carrying the identifier is almost
// never the one carrying the behaviour. The "rules per record" line in the
// output is what showed it: 12 of 13, when it should have been four.
//
// Only the top-level conjunction is walked. A selection under an or or a not
// says nothing about what the rule requires, so a rule whose identifier lives
// there keeps its place in the list that sees every record.
func requiredEventIDs(c *sigma.Compiled) []string {
	for _, name := range requiredSelections(c.Condition) {
		ids, ok := pinnedEventIDs(c.Selections[name])
		if ok {
			return ids
		}
	}
	return nil
}

// pinnedEventIDs reports the identifiers a selection restricts a record to, and
// whether it restricts it at all.
//
// Every shape of the selection has to pin it. A selection written as a list of
// maps means "any of these", so one shape that does not mention the identifier
// is a shape that matches records with any identifier at all.
func pinnedEventIDs(sel sigma.Selection) ([]string, bool) {
	if len(sel) == 0 {
		return nil, false
	}
	var ids []string
	for _, set := range sel {
		found := false
		for _, test := range set {
			if !strings.EqualFold(test.Field, "EventID") || test.Null || test.Ref != "" {
				continue
			}
			if test.All && len(test.Values) > 1 {
				// A record has one event id, so a test demanding several at
				// once can never be satisfied. Saying so here would be a
				// judgement about the rule; leaving it unindexed lets it be
				// evaluated and found silent, which is the rule author's
				// problem to see rather than this index's to hide.
				return nil, false
			}
			for _, m := range test.Values {
				exact, isExact := m.(sigma.Exact)
				if !isExact {
					// A wildcard or a regular expression over the identifier:
					// less definite than a value, so the rule keeps its place
					// in the list that sees everything.
					return nil, false
				}
				ids = append(ids, exact.Exact())
				found = true
			}
		}
		if !found {
			return nil, false
		}
	}
	return ids, len(ids) > 0
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
