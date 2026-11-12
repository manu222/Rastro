package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/report"
	"github.com/manu222/rastro/internal/sigma"
	"github.com/manu222/rastro/internal/source/auditd"
	"github.com/manu222/rastro/internal/source/evtx"
	"github.com/manu222/rastro/internal/source/winjson"
	"github.com/manu222/rastro/internal/source/zeek"
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
	in, matches, diag, err := analyse(rulesDir, evidenceDir)
	if err != nil {
		return err
	}
	// The same structure the report is rendered from, so that the two commands
	// cannot end up disagreeing about how many findings there are.
	r := report.Build(in, matches)

	fmt.Printf("Rules loaded    : %d\n", r.Evidence.RulesLoaded)
	if n := len(r.Limits.RefusedRules); n > 0 {
		fmt.Printf("Rules refused   : %d  (these are blind spots, not warnings)\n", n)
		byFeature := map[string]int{}
		for _, ref := range r.Limits.RefusedRules {
			byFeature[ref.Feature]++
		}
		causes := make([]string, 0, len(byFeature))
		for cause := range byFeature {
			causes = append(causes, cause)
		}
		sort.Strings(causes)
		for _, cause := range causes {
			fmt.Printf("  %-14s %d\n", cause, byFeature[cause])
		}
		for _, ref := range r.Limits.RefusedRules {
			fmt.Printf("  - %s: %s\n", ref.Rule, ref.Reason)
		}
	}
	fmt.Printf("Ancestors known : %d process creation(s), %d logon session(s)\n",
		diag.Processes, diag.Logons)
	// Both halves of the connection join, side by side. Either one at zero
	// means the join cannot find anything, which is worth seeing before
	// wondering why no finding mentions a flow.
	if diag.Flows > 0 || diag.HostConns > 0 {
		fmt.Printf("Connections     : %d flow(s) on the wire, %d opened by a named process\n",
			diag.Flows, diag.HostConns)
	}

	fmt.Printf("\nFiles read      : %d\n", r.Evidence.Files)
	fmt.Printf("Records         : %d\n", r.Evidence.Records)
	if r.Evidence.Records > 0 {
		fmt.Printf("Evaluations     : %d  (%.1f rules per record on average)\n",
			diag.Evaluations, float64(diag.Evaluations)/float64(r.Evidence.Records))
	}
	fmt.Printf("Elapsed         : %s\n", r.Evidence.Elapsed)
	if r.Limits.UnreadableRecords > 0 {
		fmt.Printf("Unreadable      : %d record(s)\n", r.Limits.UnreadableRecords)
		if r.Limits.FirstFailure != "" {
			fmt.Printf("  first cause   : %s\n", r.Limits.FirstFailure)
		}
	}

	fmt.Printf("\nFindings        : %d\n", len(r.Findings))
	byRule := map[string]int{}
	byLevel := map[string]string{}
	for _, f := range r.Findings {
		byRule[f.Rule]++
		byLevel[f.Rule] = f.Level
	}
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

	if len(r.Evidence.RulesSilent) > 0 {
		fmt.Printf("\nLoaded but silent: %d\n", len(r.Evidence.RulesSilent))
		for _, title := range r.Evidence.RulesSilent {
			fmt.Printf("  %s\n", title)
		}
	}

	// One example per rule rather than the first few overall. The first few are
	// whatever the directory listing happened to reach first, which over this
	// corpus meant three findings from two rules and nothing from the seven
	// others. A preview shows the shapes a report will have.
	shown := map[string]bool{}
	var preview []report.Finding
	for _, f := range r.Findings {
		if shown[f.Rule] || len(preview) >= examples {
			continue
		}
		shown[f.Rule] = true
		preview = append(preview, f)
	}
	if len(preview) > 0 {
		fmt.Printf("\nOne example of each of %d rule(s):\n", len(preview))
		for _, f := range preview {
			printFinding(f)
		}
	}
	return nil
}

// printFinding is the diagnostic view of one finding. The report renders the
// same structure properly; this is for checking that the machinery produced
// what it should.
func printFinding(f report.Finding) {
	fmt.Printf("\n  [%s] %s\n", strings.ToUpper(f.Level), f.Rule)
	// The host is left out rather than printed as a gap when the evidence does
	// not name one. An audit log carries no node name unless it was configured
	// to, and two spaces where a machine should be reads like a bug.
	if f.Host != "" {
		fmt.Printf("    %s  %s  record %d of %s\n",
			f.Time.Format("2006-01-02 15:04:05"), f.Host, f.Origin.Number, f.Origin.File)
	} else {
		fmt.Printf("    %s  record %d of %s  (the evidence names no machine)\n",
			f.Time.Format("2006-01-02 15:04:05"), f.Origin.Number, f.Origin.File)
	}
	if f.Action != "" {
		fmt.Printf("    %s", f.Action)
		switch {
		case f.Account != "" && f.AccountDeduced:
			fmt.Printf(" by %s (deduced: %s)", f.Account, f.AccountWhy)
		case f.Account != "":
			fmt.Printf(" by %s", f.Account)
		case f.AccountUnknown != "":
			fmt.Printf(" by an account this evidence does not name (%s)", f.AccountUnknown)
		}
		fmt.Println()
	}
	for _, why := range f.Why {
		fmt.Printf("    because %s = %s  (rule asked for %s)\n",
			why.Field, truncate(why.Value, 80), why.Pattern)
	}
	if len(f.Lineage) > 0 {
		fmt.Println("    how it got there:")
		for i, s := range f.Lineage {
			fmt.Printf("      %s%s", strings.Repeat("  ", i), s.Image)
			if s.Account != "" {
				fmt.Printf("   %s", s.Account)
			}
			if s.Integrity != "" {
				fmt.Printf("   %s", s.Integrity)
			}
			fmt.Printf("   record %d of %s\n", s.Origin.Number, s.Origin.File)
		}
		if !f.LineageComplete {
			fmt.Println("      (the chain stops here: the parent's creation is not in this evidence)")
		}
	}
	for _, c := range f.AccountChanges {
		fmt.Printf("    account changed from %s to %s at %s, record %d of %s\n",
			c.From, c.To, c.Process, c.Origin.Number, c.Origin.File)
	}
	if f.Entry != nil {
		fmt.Printf("    came in through logon type %s", f.Entry.Type)
		if f.Entry.TypeName != "" {
			fmt.Printf(" (%s)", f.Entry.TypeName)
		}
		if f.Entry.Address != "" {
			fmt.Printf(" from %s", f.Entry.Address)
		}
		if f.Entry.Workstation != "" {
			fmt.Printf(" on %s", f.Entry.Workstation)
		}
		fmt.Printf(" as %s, record %d of %s\n",
			f.Entry.Account, f.Entry.Origin.Number, f.Entry.Origin.File)
	}

	// What the other source saw of the same connection. The diagnostic view
	// shows the unresolved case too: this command exists to check that the
	// machinery is doing what it should, and a join that found nothing is as
	// much of an answer as one that found something.
	if o := f.Other; o != nil {
		switch {
		case o.FlowID != "":
			fmt.Printf("    on the wire: flow %s", o.FlowID)
			if o.Service != "" {
				fmt.Printf(", read as %s", o.Service)
			}
			if o.OutboundSeen {
				fmt.Printf(", %s bytes out and %s back", orUnknown(o.Sent), orUnknown(o.Received))
			} else {
				fmt.Printf(", %s back and the capture did not see the side that opened it",
					orUnknown(o.Received))
			}
			if o.State != "" {
				fmt.Printf(", state %s", o.State)
			}
			fmt.Printf(", record %d of %s\n", o.Origin.Number, o.Origin.File)
		case o.Process != "":
			fmt.Printf("    opened by %s", o.Process)
			if o.Account != "" {
				fmt.Printf(" as %s", o.Account)
			}
			fmt.Println()
		case o.Unresolved != "":
			fmt.Printf("    the other source has nothing to add: %s\n", o.Unresolved)
		}
	}

	if n := f.Network; n != nil && n.Opened > 0 {
		fmt.Printf("    %s\n", n.Summary())
		for _, c := range n.Connections {
			fmt.Printf("      %s", c.Remote)
			if c.Protocol != "" {
				fmt.Printf("/%s", c.Protocol)
			}
			if c.FlowID != "" {
				fmt.Printf("   flow %s", c.FlowID)
				if c.Service != "" {
					fmt.Printf(" (%s)", c.Service)
				}
				if c.OutboundSeen {
					fmt.Printf(", %s out / %s back", orUnknown(c.Sent), orUnknown(c.Received))
				} else {
					fmt.Printf(", %s back (outbound not captured)", orUnknown(c.Received))
				}
			} else {
				fmt.Print("   not in the network evidence")
			}
			fmt.Println()
		}
		if rest := n.Opened - len(n.Connections); rest > 0 {
			fmt.Printf("      and %d more\n", rest)
		}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// truncate shortens a value for a diagnostic line.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// walkEvidence reads every event log under root and hands each record to visit.
// Used for the pass that builds the ancestry index, where nothing is evaluated
// and nothing is counted.
func walkEvidence(root string, windows *evtx.Reader, shipped *winjson.Reader, linux *auditd.Reader, network *zeek.Reader, visit func(*event.Event)) error {
	files, _, err := evidenceFiles(root)
	if err != nil {
		return err
	}
	for _, path := range withoutDescriptions(files) {
		kind := sourceOf(path)
		if kind == sourceNone {
			continue
		}
		emit := func(e *event.Event) error {
			visit(e)
			return nil
		}
		var rerr error
		switch kind {
		case sourceEVTX:
			_, rerr = windows.ReadFile(path, emit)
		case sourceAuditd:
			_, rerr = linux.ReadFile(path, emit)
		case sourceZeek:
			_, rerr = network.ReadFile(path, emit)
		case sourceWinJSON:
			_, rerr = shipped.ReadFile(path, emit)
		}
		if rerr != nil {
			// A file that cannot be read is reported by the pass that counts;
			// here it only means fewer ancestors, and the lineages that depend
			// on it will say they are incomplete.
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", filepath.Base(path), rerr)
		}
	}
	return nil
}

// evidenceFiles lists every file under root, following links to directories.
//
// evidenceRoot resolves a link given as the root; this is the same problem one
// level down. A case put together as links to each day's collection — the way
// an incident that spans a week arrives — walked nothing under filepath.WalkDir
// and reported 0 records with exit code 0: APT29's two days, linked into one
// folder, did exactly that. Links are followed, a directory already visited by
// its real path is not entered twice so a loop ends, and a link that leads
// nowhere is returned rather than skipped, so the report can say so.
//
// The order is the directory order, sorted, so two runs over the same evidence
// read it in the same order.
func evidenceFiles(root string) (files, broken []string, err error) {
	seen := map[string]bool{}
	var walk func(dir string) error
	walk = func(dir string) error {
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return err
		}
		if seen[real] {
			return nil
		}
		seen[real] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, d := range entries {
			path := filepath.Join(dir, d.Name())
			info, err := os.Stat(path) // follows a link
			if err != nil {
				broken = append(broken, path)
				continue
			}
			if info.IsDir() {
				if err := walk(path); err != nil {
					return err
				}
				continue
			}
			files = append(files, path)
		}
		return nil
	}
	err = walk(root)
	return files, broken, err
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
	for _, c := range idx.always {
		if applies(c, e) {
			idx.scratch = append(idx.scratch, c)
		}
	}
	if id := e.Raw["EventID"]; id != "" {
		for _, c := range idx.byID[id] {
			if applies(c, e) {
				idx.scratch = append(idx.scratch, c)
			}
		}
	}
	return idx.scratch
}

// applies keeps a rule away from evidence it was not written for.
//
// Most of the public corpus states what it applies to in its logsource and
// nowhere else: a Zeek rule for dns.log has nothing in its detection to stop
// it matching an http record with a field of the same name, and a Windows rule
// has nothing to stop it matching an audit log. Running a rule against
// evidence it was not written for is not a near miss, it is a false positive
// with a rule's name on it.
//
// A rule that states nothing applies everywhere, which is what keeps the rules
// of this repository working: they name their evidence inside the detection,
// which is more explicit than a logsource and cannot be undone by a reader
// labelling a record differently.
func applies(c *sigma.Compiled, e *event.Event) bool {
	return c.Applies(e.Origin.Product, e.Origin.Service, e.Origin.Categories...)
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
