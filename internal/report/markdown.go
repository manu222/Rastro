package report

import (
	"fmt"
	"io"
	"strings"
)

// Markdown writes the report as text.
//
// It is the rendering that works everywhere: in a terminal over SSH on a
// machine with no desktop, in a pull request, in an editor, and through pandoc
// into whatever a client wants to be handed. Because it is text it also
// versions and diffs, so two analyses of the same machine a week apart can be
// compared by a tool rather than by eye.
func Markdown(w io.Writer, r *Report, sections Section) error {
	out := &writer{w: w}

	out.line("# Forensic triage report")
	out.blank()
	out.line("Generated %s from `%s`.", r.Generated.Format("2006-01-02 15:04:05 UTC"), r.Evidence.Directory)
	out.blank()

	// Level one: what was looked at, what came out, and what the analysis could
	// not do. All three, in that order, before any detail.
	out.line("## Summary")
	out.blank()
	out.line("| | |")
	out.line("| --- | --- |")
	out.line("| Evidence | %d file(s), %d record(s) |", r.Evidence.Files, r.Evidence.Records)
	if !r.Evidence.Earliest.IsZero() {
		out.line("| Covering | %s to %s |",
			r.Evidence.Earliest.Format("2006-01-02 15:04:05"),
			r.Evidence.Latest.Format("2006-01-02 15:04:05"))
	}
	if len(r.Evidence.Hosts) > 0 {
		out.line("| Machines | %s |", strings.Join(r.Evidence.Hosts, ", "))
	}
	out.line("| Rules running | %d |", r.Evidence.RulesLoaded)
	out.line("| Findings | %d |", len(r.Findings))
	if len(r.Severity) > 0 {
		var parts []string
		for _, s := range r.Severity {
			parts = append(parts, fmt.Sprintf("%d %s", s.Findings, s.Level))
		}
		out.line("| By severity | %s |", strings.Join(parts, ", "))
	}
	out.line("| Time taken | %s |", r.Evidence.Elapsed)
	out.blank()

	writeLimitsMarkdown(out, r)

	if sections.Has(SectionEntities) {
		out.line("## What is affected")
		out.blank()
		if len(r.Entities) == 0 {
			out.line("Nothing. No finding named a machine, an account or a group.")
			out.blank()
		} else {
			out.line("Ordered by severity, then by how many findings touch them. This is the")
			out.line("list to work down when deciding what to isolate.")
			out.blank()
			out.line("| | Entity | Severity | Findings | As | Rules |")
			out.line("| --- | --- | --- | --- | --- | --- |")
			for _, e := range r.Entities {
				name := e.Name
				if e.Deduced {
					// An entity that only ever appeared as a deduction is
					// marked here and not quietly listed beside the observed
					// ones.
					name += " *(deduced)*"
				}
				out.line("| %s | %s | %s | %d | %s | %s |",
					e.Kind, name, e.Worst, e.Findings,
					strings.Join(e.Roles, ", "), strings.Join(e.Rules, "; "))
			}
			out.blank()
		}
	}

	if sections.Has(SectionTactics) {
		out.line("## What the attacker was doing")
		out.blank()
		if len(r.Tactics) == 0 {
			out.line("No findings to attribute.")
			out.blank()
		} else {
			for _, t := range r.Tactics {
				out.line("### %s — %d finding(s)", title(t.Name), t.Findings)
				out.blank()
				for _, tech := range t.Techniques {
					out.line("- **%s** (%d): %s", tech.ID, tech.Findings, strings.Join(tech.Rules, "; "))
				}
				out.blank()
			}
		}
	}

	if sections.Has(SectionTimeline) {
		out.line("## How it unfolded")
		out.blank()
		if len(r.Findings) == 0 {
			out.line("No findings.")
			out.blank()
		} else {
			for i, f := range r.Findings {
				writeFindingMarkdown(out, i+1, f)
			}
		}
	}

	return out.err
}

func writeLimitsMarkdown(out *writer, r *Report) {
	l := r.Limits
	out.line("## What this analysis could not do")
	out.blank()
	out.line("Read this before the findings. A report that only lists what was found")
	out.line("invites the reader to assume the rest was clean.")
	out.blank()

	any := false
	if n := len(l.RefusedRules); n > 0 {
		any = true
		out.line("**%d rule(s) were refused and did not run.** Each one is detection this", n)
		out.line("analysis did not have:")
		out.blank()
		for _, ref := range l.RefusedRules {
			out.line("- %s — %s", ref.Rule, ref.Reason)
		}
		out.blank()
	}
	if len(r.Evidence.RulesSilent) > 0 {
		any = true
		out.line("**%d rule(s) ran and found nothing.** That is either a technique absent from",
			len(r.Evidence.RulesSilent))
		out.line("this evidence or a rule that cannot fire; the test suite is what separates")
		out.line("the two. They were: %s.", strings.Join(r.Evidence.RulesSilent, ", "))
		out.blank()
	}
	if l.UnreadableRecords > 0 || l.DamagedChunks > 0 {
		any = true
		out.line("**Evidence that was not read:** %d record(s) could not be parsed and %d chunk(s)",
			l.UnreadableRecords, l.DamagedChunks)
		out.line("were damaged and skipped.")
		if l.FirstFailure != "" {
			out.line("The first failure was: %s.", l.FirstFailure)
		}
		out.blank()
	}
	// Only the counts that are not zero. A paragraph announcing that nothing
	// went wrong reads like a machine filling in a form.
	if l.SkippedFields > 0 {
		any = true
		out.line("**Fields left out:** %d value(s) could not be rendered and were dropped from "+
			"their records. The records were kept.", l.SkippedFields)
		out.blank()
	}
	if l.UndeclaredShapes > 0 {
		any = true
		out.line("**Undeclared field shapes:** %d field name(s) arrived in a shape no provider "+
			"table describes. Their values are in the report as the parser produced them, "+
			"which may not be how the provider wrote them.", l.UndeclaredShapes)
		out.blank()
	}
	if l.ClockDisagreements > 0 {
		any = true
		out.line("**Clocks that disagree:** %d of %d record(s) that came through a log shipper "+
			"carry a provider time more than a minute from the record's own. Times from that "+
			"evidence order its events and do not date them.", l.ClockDisagreements, l.ShippedRecords)
		if l.FirstClockDisagreement != "" {
			out.line("The first was: %s.", l.FirstClockDisagreement)
		}
		out.blank()
	}
	if len(l.ShipperForms) > 0 {
		any = true
		out.line("**Fields a shipper rewrote:** a rule comparing against the form the provider " +
			"writes does not match these, and says nothing.")
		out.blank()
		for _, s := range l.ShipperForms {
			out.line("- `%s` of %s: the provider writes %s, the shipper wrote %s, in %d record(s), for example `%s`",
				s.Field, s.Producer, s.Declared, s.Written, s.Count, s.Sample)
		}
		out.blank()
	}
	if l.DeducedValues > 0 || l.IncompleteChains > 0 {
		any = true
		out.line("**How much of this is inference:** %d finding(s) name an account that was",
			l.DeducedValues)
		out.line("worked out rather than recorded, and %d process chain(s) stop because the",
			l.IncompleteChains)
		out.line("evidence stops rather than because they reached the beginning. Every")
		out.line("deduction below says which record it came from.")
		out.blank()
	}
	for _, note := range l.Notes {
		any = true
		out.line("- %s", note)
	}
	if len(l.Notes) > 0 {
		out.blank()
	}
	if !any {
		out.line("Nothing to report: every rule ran, every record was read, and no value in")
		out.line("this report was deduced.")
		out.blank()
	}
}

func writeFindingMarkdown(out *writer, n int, f Finding) {
	out.line("### %d. %s — %s", n, strings.ToUpper(f.Level), f.Rule)
	out.blank()
	out.line("%s on `%s`", f.Time.Format("2006-01-02 15:04:05"), f.Host)
	out.blank()

	if f.Action != "" {
		switch {
		case f.Account != "" && f.AccountDeduced:
			out.line("%s by **%s**, deduced: %s.", title(f.Action), f.Account, f.AccountWhy)
		case f.Account != "":
			out.line("%s by **%s**.", title(f.Action), f.Account)
		case f.AccountUnknown != "":
			out.line("%s. The evidence does not name an account: %s.", title(f.Action), f.AccountUnknown)
		default:
			out.line("%s.", title(f.Action))
		}
		out.blank()
	}

	if len(f.Why) > 0 {
		out.line("**Why it fired**")
		out.blank()
		for _, why := range f.Why {
			out.line("- `%s` = `%s` — the rule asked for `%s`", why.Field, why.Value, why.Pattern)
		}
		out.blank()
	}

	if len(f.Lineage) > 0 {
		out.line("**How it got there**")
		out.blank()
		out.line("```")
		for i, s := range f.Lineage {
			line := strings.Repeat("  ", i) + s.Image
			if s.Account != "" {
				line += "   " + s.Account
			}
			if s.Integrity != "" {
				line += "   " + s.Integrity
			}
			out.raw(line)
			if len(s.Opened) > 0 {
				out.raw(strings.Repeat("  ", i) + "  -> connected to " + strings.Join(s.Opened, ", "))
			}
		}
		if !f.LineageComplete {
			out.raw("(the chain stops here: the parent's creation is not in this evidence)")
		}
		out.line("```")
		out.blank()
	}

	for _, c := range f.AccountChanges {
		out.line("The account changed from **%s** to **%s** at `%s`, record %d of `%s`.",
			c.From, c.To, c.Process, c.Origin.Number, c.Origin.File)
		out.blank()
	}

	if f.Entry != nil {
		line := fmt.Sprintf("Came in through a logon of type %s", f.Entry.Type)
		if f.Entry.TypeName != "" {
			line += " (" + f.Entry.TypeName + ")"
		}
		if f.Entry.Address != "" {
			line += " from " + f.Entry.Address
		}
		if f.Entry.Workstation != "" {
			line += " on " + f.Entry.Workstation
		}
		if f.Entry.Account != "" {
			line += " as " + f.Entry.Account
		}
		out.line("%s, record %d of `%s`.", line, f.Entry.Origin.Number, f.Entry.Origin.File)
		out.blank()
	}

	// The other half of the connection. One sentence, because this is the
	// summary level of the report: the detail of the flow is in the record the
	// line points at.
	if o := f.Other; o != nil {
		switch {
		case o.FlowID != "":
			line := "On the wire this connection is flow `" + o.FlowID + "`"
			if o.Service != "" {
				line += ", which the network read as " + o.Service
			}
			line += ", " + crossed(o.OutboundSeen, o.Sent, o.Received)
			if o.State != "" {
				line += ", state " + o.State
			}
			out.line("%s — record %d of `%s`. %s.", line, o.Origin.Number, o.Origin.File, o.Why)
		case o.Process != "":
			line := "The host records this connection being opened by `" + o.Process + "`"
			if o.Account != "" {
				line += " as " + o.Account
			}
			out.line("%s. %s.", line, o.Why)
		case o.Unresolved != "":
			out.line("The other source has nothing to add: %s.", o.Unresolved)
		}
		out.blank()
	}

	if x := f.Executable; x != nil {
		if x.Unresolved != "" {
			out.line("Nothing more is known about the file: %s.", x.Unresolved)
		} else {
			out.line("Zeek's PE analyser read the file as %s — record %d of `%s`. %s.",
				x.Description(), x.Origin.Number, x.Origin.File, x.Why)
		}
		out.blank()
	}

	// Where the process went. This is the question a finding about a program
	// leaves open, and the answer is in records the finding itself never
	// touches.
	if n := f.Network; n != nil && n.Opened > 0 {
		out.line("%s", n.Summary())
		out.blank()
		for _, c := range n.Connections {
			line := "- " + c.Remote
			if c.Protocol != "" {
				line += " over " + c.Protocol
			}
			if c.FlowID != "" {
				line += fmt.Sprintf(", flow `%s`", c.FlowID)
				if c.Service != "" {
					line += " read as " + c.Service
				}
				line += ", " + crossed(c.OutboundSeen, c.Sent, c.Received)
			} else {
				line += ", which the network evidence does not hold"
			}
			out.line("%s", line)
		}
		if rest := n.Opened - len(n.Connections); rest > 0 {
			out.line("- and %d more", rest)
		}
		out.blank()
	}

	if len(f.Techniques) > 0 {
		out.line("ATT&CK: %s", strings.Join(f.Techniques, ", "))
		out.blank()
	}

	// Level three: where to go and read it. The record is named rather than
	// embedded, because a report that carries every field of every finding
	// stops being a report.
	out.line("Record %d of `%s`.", f.Origin.Number, f.Origin.File)
	out.blank()
}

// writer keeps the first error and gets out of the way.
type writer struct {
	w   io.Writer
	err error
}

// line writes a formatted line. The format string is applied even with no
// arguments, so a literal % in text has to be doubled, which is why most of
// the prose here avoids it.
func (x *writer) line(format string, args ...any) {
	if x.err != nil {
		return
	}
	_, x.err = fmt.Fprintf(x.w, format+"\n", args...)
}

// raw writes a line with no formatting applied, for content that may contain a
// percent sign or a brace.
func (x *writer) raw(s string) {
	if x.err != nil {
		return
	}
	_, x.err = fmt.Fprintln(x.w, s)
}

func (x *writer) blank() { x.raw("") }

// title upper-cases the first letter of a sentence without touching the rest,
// because the rest may be a path or an account name.
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
