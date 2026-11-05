package report

import (
	"html/template"
	"io"
	"strings"
)

// HTML writes the report as one self-contained page.
//
// Self-contained matters more than it sounds: a forensic report gets emailed,
// attached to a ticket and opened on a machine that is deliberately off the
// network, so a page that fetches a stylesheet from somewhere is a page that
// arrives broken. Everything is inline and there is no JavaScript, which also
// means nothing in here can make a request when the reader opens it.
//
// It renders the same structures as the Markdown writer and shows the same
// things. Neither rendering is allowed to know something the other does not:
// the moment one of them starts calculating, the two reports of the same
// analysis stop agreeing.
func HTML(w io.Writer, r *Report, sections Section) error {
	data := struct {
		*Report
		ShowEntities bool
		ShowTimeline bool
		ShowTactics  bool
	}{
		Report:       r,
		ShowEntities: sections.Has(SectionEntities),
		ShowTimeline: sections.Has(SectionTimeline),
		ShowTactics:  sections.Has(SectionTactics),
	}
	return htmlTemplate.Execute(w, data)
}

// The template escapes everything it prints, which is not a detail: the values
// in a report come out of attacker-chosen input. A command line with a script
// tag in it is a thing that happens, and html/template is what keeps a report
// from executing the evidence it is describing.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"title": title,
	"inc":   func(n int) int { return n + 1 },
	// repeat indents a step of a process lineage. It returns plain text that
	// the template escapes like any other value.
	"repeat": func(n int) string { return strings.Repeat("  ", n) },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forensic triage report</title>
<style>
:root { color-scheme: light dark; }
body { font: 15px/1.55 -apple-system, "Segoe UI", system-ui, sans-serif;
       max-width: 62rem; margin: 2rem auto; padding: 0 1.25rem; }
h1 { font-size: 1.6rem; margin-bottom: .25rem; }
h2 { font-size: 1.2rem; margin-top: 2.5rem; border-bottom: 1px solid #8884; padding-bottom: .3rem; }
h3 { font-size: 1rem; margin-top: 1.75rem; }
table { border-collapse: collapse; width: 100%; margin: .75rem 0; }
th, td { text-align: left; padding: .35rem .6rem; border-bottom: 1px solid #8883; vertical-align: top; }
th { font-weight: 600; font-size: .85rem; text-transform: uppercase; letter-spacing: .03em; opacity: .75; }
code, pre { font-family: ui-monospace, "Cascadia Code", Menlo, monospace; font-size: .88em; }
pre { background: #8881; padding: .7rem .9rem; border-radius: 4px; overflow-x: auto; }
.lvl { font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
       padding: .1rem .45rem; border-radius: 3px; border: 1px solid currentColor; }
.critical, .high { color: #c0392b; }
.medium { color: #b9770e; }
.low, .informational, .unknown { color: #5d6d7e; }
.limits { background: #8881; border-left: 3px solid #8886; padding: .8rem 1rem; border-radius: 0 4px 4px 0; }
.deduced { opacity: .8; font-style: italic; }
.meta { opacity: .75; font-size: .9em; }
.finding { margin-bottom: 2rem; }
</style>
</head>
<body>

<h1>Forensic triage report</h1>
<p class="meta">Generated {{ .Generated.Format "2006-01-02 15:04:05 UTC" }} from <code>{{ .Evidence.Directory }}</code>.</p>

<h2>Summary</h2>
<table>
<tr><th>Evidence</th><td>{{ .Evidence.Files }} file(s), {{ .Evidence.Records }} record(s)</td></tr>
{{ if not .Evidence.Earliest.IsZero }}<tr><th>Covering</th><td>{{ .Evidence.Earliest.Format "2006-01-02 15:04:05" }} to {{ .Evidence.Latest.Format "2006-01-02 15:04:05" }}</td></tr>{{ end }}
{{ if .Evidence.Hosts }}<tr><th>Machines</th><td>{{ range $i, $h := .Evidence.Hosts }}{{ if $i }}, {{ end }}<code>{{ $h }}</code>{{ end }}</td></tr>{{ end }}
<tr><th>Rules running</th><td>{{ .Evidence.RulesLoaded }}</td></tr>
<tr><th>Findings</th><td>{{ len .Findings }}{{ if .Severity }} &mdash; {{ range $i, $s := .Severity }}{{ if $i }}, {{ end }}{{ $s.Findings }} <span class="lvl {{ $s.Level }}">{{ $s.Level }}</span>{{ end }}{{ end }}</td></tr>
<tr><th>Time taken</th><td>{{ .Evidence.Elapsed }}</td></tr>
</table>

<h2>What this analysis could not do</h2>
<div class="limits">
<p>Read this before the findings. A report that only lists what was found invites
the reader to assume the rest was clean.</p>
{{ with .Limits.RefusedRules }}
<p><strong>{{ len . }} rule(s) were refused and did not run.</strong> Each one is
detection this analysis did not have:</p>
<ul>{{ range . }}<li>{{ .Rule }} &mdash; {{ .Reason }}</li>{{ end }}</ul>
{{ end }}
{{ with .Evidence.RulesSilent }}
<p><strong>{{ len . }} rule(s) ran and found nothing.</strong> That is either a
technique absent from this evidence or a rule that cannot fire; the test suite is
what separates the two. They were:
{{ range $i, $r := . }}{{ if $i }}, {{ end }}{{ $r }}{{ end }}.</p>
{{ end }}
{{ if or .Limits.UnreadableRecords .Limits.DamagedChunks }}
<p><strong>Evidence that was not read:</strong> {{ .Limits.UnreadableRecords }}
record(s) could not be parsed and {{ .Limits.DamagedChunks }} chunk(s) were
damaged and skipped.{{ with .Limits.FirstFailure }} The first failure was: {{ . }}.{{ end }}</p>
{{ end }}
{{ if or .Limits.SkippedFields .Limits.UndeclaredShapes }}
<p><strong>Fields:</strong> {{ .Limits.SkippedFields }} value(s) could not be
rendered and were left out of their records, and {{ .Limits.UndeclaredShapes }}
field name(s) arrived in a shape no provider table describes. The records were
kept either way.</p>
{{ end }}
{{ if or .Limits.DeducedValues .Limits.IncompleteChains }}
<p><strong>How much of this is inference:</strong> {{ .Limits.DeducedValues }}
finding(s) name an account that was worked out rather than recorded, and
{{ .Limits.IncompleteChains }} process chain(s) stop because the evidence stops
rather than because they reached the beginning. Every deduction below says which
record it came from.</p>
{{ end }}
{{ with .Limits.Notes }}<ul>{{ range . }}<li>{{ . }}</li>{{ end }}</ul>{{ end }}
{{ if and (not .Limits.RefusedRules) (not .Evidence.RulesSilent) (not .Limits.UnreadableRecords) (not .Limits.DeducedValues) }}
<p>Nothing to report: every rule ran, every record was read, and no value in this
report was deduced.</p>
{{ end }}
</div>

{{ if .ShowEntities }}
<h2>What is affected</h2>
{{ if .Entities }}
<p class="meta">Ordered by severity, then by how many findings touch them. This is
the list to work down when deciding what to isolate.</p>
<table>
<tr><th>Kind</th><th>Entity</th><th>Severity</th><th>Findings</th><th>As</th><th>Rules</th></tr>
{{ range .Entities }}
<tr>
<td>{{ .Kind }}</td>
<td><code>{{ .Name }}</code>{{ if .Deduced }} <span class="deduced">(deduced)</span>{{ end }}</td>
<td><span class="lvl {{ .Worst }}">{{ .Worst }}</span></td>
<td>{{ .Findings }}</td>
<td class="meta">{{ range $i, $r := .Roles }}{{ if $i }}, {{ end }}{{ $r }}{{ end }}</td>
<td class="meta">{{ range $i, $r := .Rules }}{{ if $i }}; {{ end }}{{ $r }}{{ end }}</td>
</tr>
{{ end }}
</table>
{{ else }}<p>Nothing. No finding named a machine, an account or a group.</p>{{ end }}
{{ end }}

{{ if .ShowTactics }}
<h2>What the attacker was doing</h2>
{{ if .Tactics }}
{{ range .Tactics }}
<h3>{{ title .Name }} &mdash; {{ .Findings }} finding(s)</h3>
<ul>
{{ range .Techniques }}<li><strong>{{ .ID }}</strong> ({{ .Findings }}):
{{ range $i, $r := .Rules }}{{ if $i }}; {{ end }}{{ $r }}{{ end }}</li>{{ end }}
</ul>
{{ end }}
{{ else }}<p>No findings to attribute.</p>{{ end }}
{{ end }}

{{ if .ShowTimeline }}
<h2>How it unfolded</h2>
{{ if .Findings }}
{{ range $n, $f := .Findings }}
<div class="finding">
<h3>{{ inc $n }}. <span class="lvl {{ $f.Level }}">{{ $f.Level }}</span> {{ $f.Rule }}</h3>
<p class="meta">{{ $f.Time.Format "2006-01-02 15:04:05" }} on <code>{{ $f.Host }}</code></p>
{{ with $f.Action }}
<p>{{ title . }}{{ if $f.Account }} by <strong>{{ $f.Account }}</strong>{{ if $f.AccountDeduced }}
<span class="deduced">(deduced: {{ $f.AccountWhy }})</span>{{ end }}{{ else }}{{ with $f.AccountUnknown }}.
The evidence does not name an account: {{ . }}{{ end }}{{ end }}.</p>
{{ end }}
{{ with $f.Why }}
<p><strong>Why it fired</strong></p>
<ul>{{ range . }}<li><code>{{ .Field }}</code> = <code>{{ .Value }}</code>
&mdash; the rule asked for <code>{{ .Pattern }}</code></li>{{ end }}</ul>
{{ end }}
{{ with $f.Lineage }}
<p><strong>How it got there</strong></p>
<pre>{{ range $i, $s := . }}{{ repeat $i }}{{ $s.Image }}{{ with $s.Account }}   {{ . }}{{ end }}{{ with $s.Integrity }}   {{ . }}{{ end }}
{{ end }}{{ if not $f.LineageComplete }}(the chain stops here: the parent's creation is not in this evidence)
{{ end }}</pre>
{{ end }}
{{ range $f.AccountChanges }}
<p>The account changed from <strong>{{ .From }}</strong> to <strong>{{ .To }}</strong>
at <code>{{ .Process }}</code>, record {{ .Origin.Number }} of <code>{{ .Origin.File }}</code>.</p>
{{ end }}
{{ with $f.Entry }}
<p>Came in through a logon of type {{ .Type }}{{ with .TypeName }} ({{ . }}){{ end }}{{ with .Address }}
from {{ . }}{{ end }}{{ with .Workstation }} on {{ . }}{{ end }}{{ with .Account }} as {{ . }}{{ end }},
record {{ .Origin.Number }} of <code>{{ .Origin.File }}</code>.</p>
{{ end }}
{{ with $f.Techniques }}<p class="meta">ATT&amp;CK: {{ range $i, $t := . }}{{ if $i }}, {{ end }}{{ $t }}{{ end }}</p>{{ end }}
<p class="meta">Record {{ $f.Origin.Number }} of <code>{{ $f.Origin.File }}</code>.</p>
</div>
{{ end }}
{{ else }}<p>No findings.</p>{{ end }}
{{ end }}

</body>
</html>
`))
