// Package report turns an analysis into something a person reads.
//
// There is one report and several renderings of it, which is not the same as
// several reports. The structures here hold what the analysis found and what it
// could not do; Markdown, HTML and JSON are three ways of writing that down,
// and which one is right depends on where the analyst is sitting rather than on
// anything about the evidence. A terminal over SSH wants Markdown, a desktop
// wants HTML, a SIEM wants JSON, and none of them should be able to say
// something the others cannot.
//
// The three views — the entities involved, the order things happened in, the
// techniques used — are indexes over the same findings and not three separate
// documents. An incident has one set of facts and three questions asked of it:
// what is affected and has to be isolated, how did it unfold, and what was the
// attacker doing.
//
// What the report must always carry, whichever rendering and whichever views
// were asked for, is what the analysis could not do: the rules that were
// refused, the records that could not be read, the chains that stop because the
// evidence stops, and which values were deduced rather than observed. A report
// that only lists what was found invites the reader to believe the rest was
// clean, and that is the one thing a forensic document must never do.
package report

import (
	"sort"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/correlate"
	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/sigma"
)

// Section selects a view. They are flags because the caller may want one, two
// or all three.
type Section uint8

const (
	SectionEntities Section = 1 << iota
	SectionTimeline
	SectionTactics
)

// AllSections is every view, which is the default.
const AllSections = SectionEntities | SectionTimeline | SectionTactics

// Has reports whether a set of sections includes one.
func (s Section) Has(want Section) bool { return s&want != 0 }

// ParseSections reads a comma-separated list: "entities,timeline".
func ParseSections(list string) (Section, error) {
	if strings.TrimSpace(list) == "" || list == "all" {
		return AllSections, nil
	}
	var out Section
	for _, name := range strings.Split(list, ",") {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "entities", "entidades":
			out |= SectionEntities
		case "timeline", "linea", "cronologia":
			out |= SectionTimeline
		case "tactics", "tacticas", "attack":
			out |= SectionTactics
		case "":
		default:
			return 0, &UnknownSection{Name: name}
		}
	}
	if out == 0 {
		return 0, &UnknownSection{Name: list}
	}
	return out, nil
}

// UnknownSection is returned for a view nobody has.
type UnknownSection struct{ Name string }

func (e *UnknownSection) Error() string {
	return "unknown section " + e.Name + "; the views are entities, timeline and tactics"
}

// Report is the analysis, ready to be written down.
type Report struct {
	// Evidence says what was analysed. It is first because a finding means
	// nothing without knowing what it was found in.
	Evidence Evidence `json:"evidence"`
	// Findings are every match, in the order they happened.
	Findings []Finding `json:"findings"`
	// Limits is what the analysis could not do.
	Limits Limits `json:"limits"`

	// The three views, built from Findings.
	Entities []Entity   `json:"entities"`
	Tactics  []Tactic   `json:"tactics"`
	Severity []Severity `json:"severity"`

	Generated time.Time `json:"generated"`
}

// Evidence describes the input.
type Evidence struct {
	Directory string    `json:"directory"`
	Files     int       `json:"files"`
	Records   int       `json:"records"`
	Earliest  time.Time `json:"earliest"`
	Latest    time.Time `json:"latest"`
	// Hosts is every machine the evidence names, whether or not anything was
	// found on it. A machine with no findings is information: it was looked at.
	Hosts []string `json:"hosts"`
	// RulesLoaded and RulesSilent say how much detection was actually running.
	RulesLoaded int      `json:"rules_loaded"`
	RulesSilent []string `json:"rules_silent"`
	Elapsed     string   `json:"elapsed"`
}

// Limits is the honest half of the report.
type Limits struct {
	// RefusedRules are rules that could not be run at all. Each one is
	// detection the analysis did not have.
	RefusedRules []Refusal `json:"refused_rules"`
	// UnreadableRecords and DamagedChunks are evidence that was not read.
	UnreadableRecords int    `json:"unreadable_records"`
	DamagedChunks     int    `json:"damaged_chunks"`
	FirstFailure      string `json:"first_failure,omitempty"`
	// SkippedFields counts values that could not be rendered. The records were
	// kept.
	SkippedFields int `json:"skipped_fields"`
	// UndeclaredShapes counts fields that arrived in a shape no provider table
	// describes.
	UndeclaredShapes int `json:"undeclared_shapes"`
	// DeducedValues and IncompleteChains quantify how much of the report rests
	// on inference rather than on what was recorded.
	DeducedValues    int `json:"deduced_values"`
	IncompleteChains int `json:"incomplete_chains"`
	// Notes are the blind spots that are properties of the method rather than
	// of this run.
	Notes []string `json:"notes,omitempty"`
}

// Refusal is one rule that did not load.
type Refusal struct {
	Rule    string `json:"rule"`
	Feature string `json:"feature"`
	Reason  string `json:"reason"`
}

// Finding is one match, with everything needed to check it.
type Finding struct {
	Time   time.Time `json:"time"`
	Rule   string    `json:"rule"`
	RuleID string    `json:"rule_id,omitempty"`
	Level  string    `json:"level"`
	// Tactics and Techniques come from the rule's ATT&CK tags.
	Tactics    []string `json:"tactics,omitempty"`
	Techniques []string `json:"techniques,omitempty"`

	Host   string `json:"host,omitempty"`
	Action string `json:"action,omitempty"`

	// Account is who was behind it, and Deduced says whether that was read or
	// worked out. A report that cannot tell those apart cannot be checked.
	Account        string `json:"account,omitempty"`
	AccountDeduced bool   `json:"account_deduced"`
	AccountWhy     string `json:"account_why,omitempty"`
	// AccountUnknown explains a missing account, so that a blank is never left
	// to be interpreted.
	AccountUnknown string `json:"account_unknown,omitempty"`

	// Why is what the rule matched on: the field, its value, the pattern.
	Why []Reason `json:"why"`

	// Lineage is the chain of processes above the event, oldest first.
	Lineage []Step `json:"lineage,omitempty"`
	// LineageComplete reports whether the chain reached a process with no
	// parent, or simply ran out of evidence.
	LineageComplete bool `json:"lineage_complete"`
	// AccountChanges are the points in the lineage where the account changed,
	// which is what "how did this get to SYSTEM" means in practice.
	AccountChanges []AccountChange `json:"account_changes,omitempty"`
	// Entry is the oldest logon session in the lineage: where it came from.
	Entry *EntryPoint `json:"entry,omitempty"`

	// Involved are the entities this finding touches, which is how the report
	// is grouped.
	Involved []Involvement `json:"involved,omitempty"`

	// Origin points back at the record, so that level three of the report can
	// show it and anyone can go and read it themselves.
	Origin Record `json:"origin"`
}

// Reason is one field that satisfied the rule.
type Reason struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Pattern string `json:"pattern"`
}

// Step is one process of a lineage.
type Step struct {
	Image       string `json:"image"`
	CommandLine string `json:"command_line,omitempty"`
	Account     string `json:"account,omitempty"`
	Integrity   string `json:"integrity,omitempty"`
	Origin      Record `json:"origin"`
}

// AccountChange is a point where the account changed between a process and its
// child. It is deliberately not called an escalation: a service starting as
// SYSTEM under services.exe has the same shape as a token theft, and which one
// it was is the reader's call.
type AccountChange struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Process string `json:"process"`
	Origin  Record `json:"origin"`
}

// EntryPoint is the logon the lineage started from.
type EntryPoint struct {
	Account     string `json:"account,omitempty"`
	Type        string `json:"type,omitempty"`
	TypeName    string `json:"type_name,omitempty"`
	Address     string `json:"address,omitempty"`
	Workstation string `json:"workstation,omitempty"`
	Origin      Record `json:"origin"`
}

// Involvement is an entity and what it was to a finding.
type Involvement struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Role  string `json:"role,omitempty"`
	Known bool   `json:"observed"`
}

// Record identifies one record of the evidence.
type Record struct {
	File     string `json:"file"`
	Number   int64  `json:"record"`
	Producer string `json:"producer,omitempty"`
}

// Entity is one thing the incident touched, with everything found about it.
type Entity struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Findings int      `json:"findings"`
	Worst    string   `json:"worst_level"`
	Rules    []string `json:"rules"`
	// Roles are the parts it played: target, actor, parent image.
	Roles []string `json:"roles,omitempty"`
	// Deduced marks an entity that only ever appeared as a deduction.
	Deduced bool `json:"deduced"`
}

// Tactic groups findings by ATT&CK tactic and technique.
type Tactic struct {
	Name       string      `json:"name"`
	Findings   int         `json:"findings"`
	Techniques []Technique `json:"techniques"`
}

// Technique is one technique under a tactic.
type Technique struct {
	ID       string   `json:"id"`
	Findings int      `json:"findings"`
	Rules    []string `json:"rules"`
}

// Severity counts findings by level.
type Severity struct {
	Level    string `json:"level"`
	Findings int    `json:"findings"`
}

// Input is everything a caller has to supply to build a report. It is a struct
// rather than a long argument list because it will grow: the network source and
// the Linux reader both land here.
type Input struct {
	Directory string
	Files     int
	Records   int
	Earliest  time.Time
	Latest    time.Time
	Hosts     []string
	Elapsed   time.Duration

	Loaded  []*sigma.Compiled
	Refused []*sigma.Unsupported
	Silent  []string

	UnreadableRecords int
	DamagedChunks     int
	FirstFailure      string
	SkippedFields     int
	UndeclaredShapes  int

	Notes []string
}

// Match is one finding as the detection stage produces it, before the report
// decides how to present it.
type Match struct {
	Rule    *sigma.Compiled
	Event   *event.Event
	Hits    []sigma.Hit
	Account event.Field
	// Unknown explains a missing account.
	Unknown string
	Lineage []correlate.Step
	// Complete reports whether the lineage reached a root.
	Complete bool
	Changes  []correlate.Escalation
	Entry    *correlate.Logon
	EntryWho event.Field
}

// Build turns an analysis into a report.
func Build(in Input, matches []Match) *Report {
	r := &Report{
		Generated: time.Now().UTC(),
		Evidence: Evidence{
			Directory:   in.Directory,
			Files:       in.Files,
			Records:     in.Records,
			Earliest:    in.Earliest,
			Latest:      in.Latest,
			Hosts:       in.Hosts,
			RulesLoaded: len(in.Loaded),
			RulesSilent: in.Silent,
			Elapsed:     in.Elapsed.Round(time.Millisecond).String(),
		},
		Limits: Limits{
			UnreadableRecords: in.UnreadableRecords,
			DamagedChunks:     in.DamagedChunks,
			FirstFailure:      in.FirstFailure,
			SkippedFields:     in.SkippedFields,
			UndeclaredShapes:  in.UndeclaredShapes,
			Notes:             in.Notes,
		},
	}
	for _, u := range in.Refused {
		r.Limits.RefusedRules = append(r.Limits.RefusedRules, Refusal{
			Rule: u.Title, Feature: u.Feature, Reason: u.Reason,
		})
	}

	for _, m := range matches {
		r.Findings = append(r.Findings, buildFinding(m))
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Time.Before(r.Findings[j].Time)
	})

	for _, f := range r.Findings {
		if f.AccountDeduced {
			r.Limits.DeducedValues++
		}
		if len(f.Lineage) > 0 && !f.LineageComplete {
			r.Limits.IncompleteChains++
		}
	}

	r.Entities = buildEntities(r.Findings)
	r.Tactics = buildTactics(r.Findings)
	r.Severity = buildSeverity(r.Findings)
	return r
}

func buildFinding(m Match) Finding {
	e := m.Event
	f := Finding{
		Time:   e.Time,
		Rule:   m.Rule.Rule.Title,
		RuleID: m.Rule.Rule.ID,
		Level:  level(m.Rule.Rule.Level),
		Host:   e.Host.Value,
		Action: e.Action,
		Origin: Record{File: e.Origin.Path, Number: e.Origin.Record, Producer: e.Origin.Producer},
	}
	f.Tactics, f.Techniques = attack(m.Rule.Rule.Tags)

	if m.Account.Known() {
		f.Account = m.Account.Value
		f.AccountDeduced = !m.Account.Trusted()
		f.AccountWhy = m.Account.Why
	} else {
		f.AccountUnknown = m.Unknown
	}

	for _, h := range m.Hits {
		f.Why = append(f.Why, Reason{Field: h.Field, Value: oneLine(h.Value), Pattern: h.Pattern})
	}

	// Oldest first, which is the order it happened in, and without the step
	// that is the event itself.
	for i := len(m.Lineage) - 1; i >= 0; i-- {
		p := m.Lineage[i].Process
		if p.Origin.Path == e.Origin.Path && p.Origin.Record == e.Origin.Record {
			continue
		}
		f.Lineage = append(f.Lineage, Step{
			Image:       p.Image,
			CommandLine: oneLine(p.CommandLine),
			Account:     p.User,
			Integrity:   p.Integrity,
			Origin:      Record{File: p.Origin.Path, Number: p.Origin.Record},
		})
	}
	f.LineageComplete = m.Complete

	for _, c := range m.Changes {
		f.AccountChanges = append(f.AccountChanges, AccountChange{
			From: c.FromUser, To: c.ToUser, Process: c.To.Image,
			Origin: Record{File: c.To.Origin.Path, Number: c.To.Origin.Record},
		})
	}

	if m.Entry != nil {
		name, _ := logonTypeName(m.Entry.Type)
		f.Entry = &EntryPoint{
			Account:     m.EntryWho.Value,
			Type:        m.Entry.Type,
			TypeName:    name,
			Address:     clean(m.Entry.Address),
			Workstation: clean(m.Entry.Workstation),
			Origin:      Record{File: m.Entry.Origin.Path, Number: m.Entry.Origin.Record},
		}
	}

	f.Involved = involvement(e, m.Account)
	return f
}

// involvement collects the entities a finding touches. The host and the account
// are included explicitly, because they are the two a reader asks for first and
// they do not always arrive as entities of the event.
func involvement(e *event.Event, account event.Field) []Involvement {
	var out []Involvement
	seen := map[string]bool{}
	add := func(kind, name, role string, known bool) {
		if name == "" {
			return
		}
		key := kind + "\x00" + name + "\x00" + role
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Involvement{Kind: kind, Name: name, Role: role, Known: known})
	}

	add("host", e.Host.Value, "", e.Host.Trusted())
	if account.Known() {
		add("account", account.Value, "actor", account.Trusted())
	}
	for _, ent := range e.Entities {
		add(ent.Kind.String(), ent.Field.Value, ent.Role, ent.Field.Trusted())
	}
	return out
}

// buildEntities is the view that answers "what is affected".
func buildEntities(findings []Finding) []Entity {
	type key struct{ kind, name string }
	index := map[key]*Entity{}
	roles := map[key]map[string]bool{}
	rules := map[key]map[string]bool{}

	for _, f := range findings {
		for _, inv := range f.Involved {
			// A logon session is a join key and not a thing anybody isolates.
			// It belongs on the finding, where it ties events together, and
			// not in the list of what is affected, where "session 999" sits
			// between two machines and means nothing to the reader.
			if inv.Kind == "session" {
				continue
			}
			k := key{inv.Kind, identity(inv.Kind, inv.Name)}
			ent := index[k]
			if ent == nil {
				// The first spelling seen is the one shown, because any of
				// them is as good as the others and picking one keeps the
				// report stable between runs.
				ent = &Entity{Kind: inv.Kind, Name: inv.Name, Deduced: !inv.Known}
				index[k] = ent
				roles[k] = map[string]bool{}
				rules[k] = map[string]bool{}
			}
			ent.Findings++
			// An entity seen observed even once is not a deduction.
			if inv.Known {
				ent.Deduced = false
			}
			if worse(f.Level, ent.Worst) {
				ent.Worst = f.Level
			}
			if inv.Role != "" {
				roles[k][inv.Role] = true
			}
			rules[k][f.Rule] = true
		}
	}

	out := make([]Entity, 0, len(index))
	for k, ent := range index {
		ent.Roles = sortedKeys(roles[k])
		ent.Rules = sortedKeys(rules[k])
		out = append(out, *ent)
	}
	// Worst first, then most findings, then by name, so the top of the list is
	// what to look at and the order does not change between runs.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Worst != out[j].Worst {
			return worse(out[i].Worst, out[j].Worst)
		}
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		if out[i].Kind != out[j].Kind {
			return kindOrder(out[i].Kind) < kindOrder(out[j].Kind)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// buildTactics is the view that answers "what was the attacker doing".
// identity decides when two names are the same thing.
//
// A machine name, an account and a hex digest are case-insensitive by their own
// nature: DNS does not distinguish them, Windows does not distinguish accounts,
// and a digest is a number written in hexadecimal. Without this the report
// listed insecurebank\Administrator and insecurebank\administrator as two
// accounts with four findings and one, which understates both and invites the
// reader to think there were two.
//
// Paths are deliberately left alone. Windows does not distinguish their case
// either, but Linux does, and there is no reader for Linux evidence yet to say
// which rule applies to a given path. Merging them now would be a guess that
// becomes wrong the day that reader lands; the consequence meanwhile is that
// one file can appear twice, which is visible rather than silent.
func identity(kind, name string) string {
	switch kind {
	case "host", "account", "group", "hash", "domain":
		return strings.ToLower(name)
	}
	return name
}

func buildTactics(findings []Finding) []Tactic {
	tactics := map[string]*Tactic{}
	techniques := map[string]map[string]*Technique{}
	rules := map[string]map[string]map[string]bool{}

	for _, f := range findings {
		names := f.Tactics
		if len(names) == 0 {
			// A rule with no tactic tag is not dropped: it would disappear from
			// this view and the reader would never know it fired.
			names = []string{"untagged"}
		}
		for _, name := range names {
			t := tactics[name]
			if t == nil {
				t = &Tactic{Name: name}
				tactics[name] = t
				techniques[name] = map[string]*Technique{}
				rules[name] = map[string]map[string]bool{}
			}
			t.Findings++
			ids := f.Techniques
			if len(ids) == 0 {
				ids = []string{"untagged"}
			}
			for _, id := range ids {
				tech := techniques[name][id]
				if tech == nil {
					tech = &Technique{ID: id}
					techniques[name][id] = tech
					rules[name][id] = map[string]bool{}
				}
				tech.Findings++
				rules[name][id][f.Rule] = true
			}
		}
	}

	out := make([]Tactic, 0, len(tactics))
	for name, t := range tactics {
		for id, tech := range techniques[name] {
			tech.Rules = sortedKeys(rules[name][id])
			t.Techniques = append(t.Techniques, *tech)
		}
		sort.Slice(t.Techniques, func(i, j int) bool { return t.Techniques[i].ID < t.Techniques[j].ID })
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func buildSeverity(findings []Finding) []Severity {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Level]++
	}
	order := []string{"critical", "high", "medium", "low", "informational", "unknown"}
	var out []Severity
	for _, lvl := range order {
		if counts[lvl] > 0 {
			out = append(out, Severity{Level: lvl, Findings: counts[lvl]})
		}
	}
	return out
}

// attack splits a rule's tags into tactics and techniques.
//
// Sigma writes them in one namespace — attack.credential_access,
// attack.t1003.001 — and which is which is decided by the shape of the name: a
// technique starts with t and a digit. Tags that are neither are left out of
// this view rather than guessed at.
func attack(tags []string) (tactics, techniques []string) {
	for _, tag := range tags {
		rest, ok := cutPrefix(strings.ToLower(tag), "attack.")
		if !ok {
			continue
		}
		if len(rest) > 1 && rest[0] == 't' && rest[1] >= '0' && rest[1] <= '9' {
			techniques = append(techniques, strings.ToUpper(rest))
			continue
		}
		tactics = append(tactics, strings.ReplaceAll(rest, "_", " "))
	}
	sort.Strings(tactics)
	sort.Strings(techniques)
	return tactics, techniques
}

func cutPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// logonTypeName translates the logon type of an entry point. The table is the
// documented enumeration; a number that is not in it stays a number.
func logonTypeName(v string) (string, bool) {
	switch v {
	case "2":
		return "interactive", true
	case "3":
		return "network", true
	case "4":
		return "batch", true
	case "5":
		return "service", true
	case "7":
		return "unlock", true
	case "8":
		return "network cleartext", true
	case "9":
		return "new credentials", true
	case "10":
		return "remote interactive", true
	case "11":
		return "cached interactive", true
	}
	return "", false
}

var levels = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1,
}

func level(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := levels[s]; !ok {
		return "unknown"
	}
	return s
}

// worse reports whether a is more serious than b.
func worse(a, b string) bool { return levels[a] > levels[b] }

func kindOrder(kind string) int {
	switch kind {
	case "host":
		return 0
	case "account":
		return 1
	case "group":
		return 2
	case "session":
		return 3
	}
	return 4
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// oneLine collapses the whitespace of a value that is not a line. Some fields
// hold lists separated by newlines and tabs, and printed as they stand they
// break the line they are supposed to explain. The whitespace is collapsed
// rather than stripped, so what is shown is still the value.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// clean drops the placeholders Windows writes where it has nothing to say, so
// that a report never shows an address of "-".
func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "-" || s == "?" {
		return ""
	}
	return s
}
