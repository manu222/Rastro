# Rastro

[![CI](https://github.com/manu222/Rastro/actions/workflows/ci.yml/badge.svg)](https://github.com/manu222/Rastro/actions/workflows/ci.yml)

Forensic triage tool: give it the evidence from an incident — packet captures,
Windows event logs, system logs — and it returns a single correlated timeline
mapped to MITRE ATT&CK, in a report that reads equally well for a junior analyst
and for the person who has to make the call.

> **Status: it reads Windows event logs, Linux audit logs and Zeek logs, end to
> end.** Point it at a directory of evidence and it reads the records, works out
> what they mean, runs Sigma rules of its own against them, walks back up the
> process chain to say who was behind each finding and where they came in, and
> writes a report as Markdown, HTML or JSON. What is missing is the correlation
> *across* sources — the join that ties a DNS lookup to the process that made
> it — and rules of this repository's own for the network side.

## Why

Every evidence source already has a good tool, and they all work well on their
own: Zeek for network traffic, Hayabusa for Windows events. What none of them do
is cross-reference each other. Working out that the DNS lookup at 14:02 and the
process creation at 14:03 belong to the same incident is done today by a person,
by hand, with several windows open.

Rastro does not reimplement those tools. It contributes the part that is
missing: correlation across sources, and the story that comes out of it.

## What it does today

Over the pinned corpus — 132 event log files, 31,243 records:

```
$ rastro read datasets/
Files read      : 132
Records         : 31243
Per record      : 30.4µs
Provider's time : 996 of 31243 record(s) state when the event happened
Other blocks    : UserData/LogFileCleared                  12 record(s)
Classified      : 1310 of 31243 record(s)
Undeclared field shapes: 63

$ rastro detect datasets/
Rules loaded    : 13
Ancestors known : 476 process creation(s), 23 logon session(s)
Evaluations     : 127232  (4.1 rules per record on average)
Findings        : 45

  [HIGH] Child Process Of A Windows Accessibility Tool
    2019-03-19 20:58:44  PC01.example.corp  record 155 of Persistence/...
    process created by NT AUTHORITY\SYSTEM
    because ParentImage = C:\osk.exe  (rule asked for *\osk.exe)
    how it got there:
      C:\Windows\System32\smss.exe        NT AUTHORITY\SYSTEM   System
        C:\Windows\System32\winlogon.exe  NT AUTHORITY\SYSTEM   System
          C:\Windows\System32\Utilman.exe NT AUTHORITY\SYSTEM   System
            C:\osk.exe                     NT AUTHORITY\SYSTEM   System
      (the chain stops here: the parent's creation is not in this evidence)
```

That chain is the tool doing the thing it exists for. The rule fired on one
record; the four lines under it came from four others, found by following the
process identifiers back up. And the path is the finding: the on-screen keyboard
is at `C:\osk.exe` rather than in System32, and it was reached through
`Utilman.exe`, which is the logon screen.

The report is the same analysis written for somebody else to read:

```
$ rastro report -out report.html datasets/
$ rastro report -sections entities,timeline datasets/      # to a terminal
$ rastro report -out findings.json datasets/               # for a pipeline
```

Three renderings and three views, because where the analyst is sitting decides
what is useful: Markdown in a terminal over SSH, a self-contained HTML page on a
laptop or in an email, JSON for whatever comes next. The views are what is
affected, how it unfolded, and what the attacker was doing; any one, any two, or
all three.

Every number in that output is there because the alternative is a tool that
reports a confident zero. `0 unreadable` is a claim worth printing; so is
`1310 of 31243`, because "records read" and "records understood" are different
things and a report must not blur them.

## What is here

| Path | Contents |
| --- | --- |
| `cmd/rastro/` | The tool: `rastro read`, `rastro detect` and `rastro report` |
| `internal/source/evtx/` | Reads Windows event logs, with per-file limits and a damaged-chunk count that never aborts a file |
| `internal/source/auditd/` | Reads Linux audit logs, in the three styles the corpus contains |
| `internal/source/zeek/` | Reads Zeek logs, both the TSV and the JSON form |
| `internal/source/winjson/` | Reads Windows events as a log shipper wrote them, `.json` and `.json.gz`, with an audit of field forms and clocks |
| `internal/winevent/` | What a Windows record means: flattening, 46 mapped event ids, the translations |
| `internal/normalise/` | Restores the text a provider wrote when the parser changed its shape |
| `internal/event/` | The event model, including where each value came from |
| `internal/sigma/` | Rule loader and engine |
| `internal/correlate/` | Who was behind a finding, how it got there, and where it came in |
| `internal/report/` | One report, three renderings, three views |
| `rules/windows/`, `rules/linux/`, `rules/network/` | The detection rules |
| `tests/` | One manifest per rule: which samples it must match, and how many times |
| `templates/` | A rule skeleton per telemetry source, carrying the real field names |
| `internal/ruletest/` | The harness that runs every rule against its manifest |
| `cmd/rastro-spike/` | The feasibility probe that came first, kept for what it found |
| `scripts/` | Local checks, corpus fetchers, and the provider manifest export |
| `tools/`, `datasets/`, `datasets-linux/`, `datasets-compound/` | External tools and public evidence, not versioned |

## The rule engine

A rule is only run against the evidence it was written for. Most of the public
corpus states that in its `logsource` and nowhere else — a Zeek rule for
`dns.log` has nothing in its detection to stop it matching an HTTP record with
a field of the same name — so every event carries what kind of evidence it is,
in Sigma's own vocabulary, and a rule that names a product or a service only
sees matching records. A rule that names nothing applies everywhere, which is
what keeps the rules here working: they identify their evidence inside the
detection, which is more explicit and cannot be undone by a reader labelling a
record differently.

Rules are loaded, compiled and run in this repository rather than handed to an
external program. The reason is not pride: a tool that shells out to another
binary inherits its installation, its output format and its idea of what a rule
means, and the part of this project worth building is the traceability from a
finding back to the record that caused it.

**Measured against the 3,807 rules SigmaHQ ships, 3,780 load: 99.3%.** The
figure is a test and not a claim — clone the corpus and it measures again:

```
git clone --depth 1 https://github.com/SigmaHQ/sigma tools/sigmahq
go test ./internal/sigma/ -run Corpus -v
```

Supported: `contains`, `startswith`, `endswith`, `all`, `re` with its flags,
`cidr`, `windash`, `base64offset`, `base64`, `utf16`, `fieldref`, `cased`,
`expand`, wildcards inside values, comparison against null, keyword selections,
and a condition grammar of `and`/`or`/`not`, parentheses and `1 of`/`all of`
over a prefix.

The 27 rules that do not load all want a placeholder table — which machines are
domain controllers, which addresses are expected — and they load as soon as one
is supplied. That number describes a configuration, not the engine.

Two things were taken from the reference implementation rather than worked out,
because working them out was wrong the first time:

- The **base64 offset trim table**. The arithmetic looked right and was a
  character short, which made every such rule match *more* than its author
  asked for. Nothing would have looked broken.
- The **escaping rules**. A backslash before an asterisk escapes it and
  disappears, so `C:\Users\*\AppData` matches a literal asterisk and not any
  user's folder. An engine that decided to be helpful there would fire where
  every other Sigma backend stays quiet.

A rule the engine cannot evaluate is **refused by name, with the reason**, and
the refusals are printed beside the findings. A rule that does not load is a
line somebody reads. A rule that loads and never fires is indistinguishable
from a rule with nothing to find, and that is the failure this whole repository
is arranged to prevent.

## Coverage

### Detection rules

**15 rules, 13 ATT&CK techniques, 7 tactics.** Every one is executed against
public attack samples on each commit, and what is recorded is not a count but a
list: which sample file produces which hits. The Windows rules are checked
against Hayabusa and the Linux ones against Zircolite; the network rule has no
independent engine that reads Zeek, so its manifest checks rastro alone and
says so.

| Technique | Rule | Platform | Hits |
| --- | --- | --- | --- |
| T1003.001 · LSASS Memory | LSASS memory access with read rights | Windows | 21 |
| T1003.001 · LSASS Memory | Process memory dumped through comsvcs.dll | Windows | 1 |
| T1003.006 · DCSync | Directory replication requested by a user account | Windows | 3 |
| T1036.005 · Match Legitimate Name or Location | services.exe executed from a non-standard path | Windows | 0 |
| T1053.003 · Cron | Scheduled task persistence through cron | Linux | 9 |
| T1105 · Ingress Tool Transfer | Windows executable transferred over cleartext HTTP | Zeek | 6 |
| T1218.011 · Rundll32 | rundll32.exe proxy execution | Windows | 11 |
| T1218.011, T1055 · Rundll32, Process Injection | rundll32.exe started with no arguments | Windows | 1 |
| T1546.008 · Accessibility Features | Child process of a Windows accessibility tool | Windows | 2 |
| T1547.001 · Registry Run Keys | Autostart registry value set | Windows | 2 |
| T1569.002 · Service Execution | PsExec style service pipes | Windows | 6 |
| T1574.006 · Dynamic Linker Hijacking | LD_PRELOAD and /etc/ld.so.preload | Linux | 10 |
| T1685 · Disable or Modify Tools | UAC policy weakened via registry | Windows | 1 |
| T1685 · Disable or Modify Tools | Security service stopped | Linux | 21 |
| T1685.005 · Clear Windows Event Logs | Windows event log cleared | Windows | 12 |

Some techniques are covered by more than one rule, which is why fifteen rules
map to thirteen techniques. The services.exe rule matching nothing is not a mistake:
there is no sample of that technique in the corpus, and what keeps the rule
honest is the negative control described below.

### Windows events

46 event identifiers are mapped to what they mean — which field holds the
process that acted, which holds the one it acted on, which account was behind
it, and which values a report is organised by. All of Sysmon, 24 of the Security
channel, service state, PowerShell script blocks, and the two events that report
the log was cleared.

Three of those entries exist only because the records were read rather than
remembered: a Sysmon 6 carries no process at all, a Sysmon 10 spells a field
`SourceProcessGUID` where a Sysmon 8 spells it `SourceProcessGuid`, and on a
Security 4732 `TargetUserName` is the group rather than an account.

## What it does not cover

Detection and noise are the same dial. Turning it up until nothing is missed
produces so many false alerts that nobody reads them, at which point attacks go
unnoticed again — by design this time. So the promise here is not completeness.
It is that the gaps are written down.

**In the rules:**

- **PPLdump opens LSASS with `0x1000`**, without read access, so the LSASS rule
  does not see it. Widening the mask is not the fix: ordinary processes request
  that right.
- **DCSync from a computer account** is excluded, because domain controllers
  replicate with each other constantly. Half the matching events in the corpus
  are that legitimate replication.
- **rundll32 through an export not on the list** passes unseen. A list of known
  abuses ages; rundll32 started with no arguments at all is a rule of its own,
  at a higher level, because it does not depend on one.
- **`shell32.dll,Control_RunDLL` is deliberately left out** of the same rule: it
  is how Windows opens every Control Panel applet, and including it would mean
  an alert every time somebody changes a setting.

**In the engine:**

- **Aggregations, `near`, and correlation rules are refused.** All three
  describe a relationship across events over a window of time, which this
  engine does not keep yet. They are counted and named, not skipped.
- **Go's regular expressions are RE2**, which has no backreferences and no
  lookaround, while Sigma assumes PCRE. Every pattern is compiled when the rule
  is loaded and the rule is refused if it cannot be, so the difference is never
  discovered halfway through a case. None of the 230 patterns in the public
  corpus hits it today.

**In the evidence:**

- **auditd carries no machine name** unless it was configured to, and the
  samples were not, so findings from Linux evidence name no host. The file name
  is not a hostname, however tempting.
- **auditd records written as `unit= auditd`**, with a space after the equals
  sign, produce no `unit` field at all, so three of the eight events in one
  sample are invisible to the rule that looks for stopped services. A detection
  pipeline is only as good as the parser underneath it.
- **Sysmon writes its WMI events with the values quoted and the backslashes
  doubled**: `Destination  "c:\\Windows\\System32\\cmd.exe"`. A rule matching a
  plain path against a Sysmon 19, 20 or 21 will never fire. Sysmon does that,
  not this tool, and the values are matched as written on purpose: every other
  Sigma backend sees the same text, and rewriting it would make rastro disagree
  with them on the same evidence. The report says so in every run.
- **Message-table codes are translated only from a source.** Every `%%NNNN` in
  the pinned corpus is resolved — the last eleven read out of `msobjs.dll` on a
  real installation — and a code from other evidence that no source covers is
  shown as written. An untranslated code is a gap the reader can look up; a
  wrong label is one they cannot catch.
- **Linux rules written for Sysmon for Linux** ask for fields auditd does not
  write. `CommandLine` comes from the EXECVE arguments and `Image` from the
  SYSCALL of the same event, both recorded; an EXECVE whose SYSCALL is not in
  the evidence has no `Image` and the report counts it. `file_event` and
  `network_connection` are not offered auditd records at all: they ask for
  `Initiated` and `DestinationHostname`, which auditd never records, and
  inventing them is not on the table.
- **A process chain is only as long as the evidence.** Over a corpus of
  single-technique samples most of them stop after one or two steps and say so;
  over a full capture of one machine they reach the logon. The report counts
  how many stopped short rather than letting the reader assume they reached the
  beginning.
- **The join between host and network is on the five-tuple, never on time.**
  The two sources keep their own clocks, and evidence that went through a
  shipper can be days off; a tuple shared by two flows is reported as ambiguous
  rather than broken by a clock. From the flow, Zeek's `uid` reaches `files.log`
  and its `fuid` reaches `pe.log`, both written by Zeek.
- **One rule of this repository for the network side**, a Windows executable
  over cleartext HTTP. It has no independent engine to check it against, and
  its manifest says so.

Each of these also lives in the rule, the manifest or the code it belongs to,
not only here.

## Using it with your own rules

The rules in `rules/` are a reference set and the test bench that proves the
engine end to end: each has a manifest that CI checks against real evidence.
They are not meant to be the rules a given SOC runs. Point the tool at your own:

```
rastro report -rules /path/to/your/rules -format html -out report.html /path/to/evidence
```

Anything the engine cannot run is refused when it loads and listed in the
report, so a rule that would never fire does not count as coverage. Tuning for
your environment — excluding your own EDR from a process-access rule, say —
belongs in a filter of your rule, the way the reference LSASS rule filters
`services.exe`, not in a narrower detection.

## Performance

Measured on a two-vCPU container over the compound corpus (Windows events
through a shipper, gzipped, plus Zeek logs): one campaign of 53,952 records in
4.0 s at a 13 MB peak; the seven campaigns, 364,406 records, in 25.9 s at
27 MB; three copies of them, 1,093,218 records, in 77.6 s at 46 MB. About 14,000
records a second, linear in time, and memory bounded by the ancestry and flow
indexes rather than by the evidence: events are built, matched and dropped.

## Detection rules

Rules follow the [Sigma](https://sigmahq.io) format and are validated against
real attack logs. The guiding principle is to detect **behaviour** rather than
artefacts: a rule keyed on a tool's filename stops working the moment an
attacker renames it, while a rule keyed on what the technique cannot avoid doing
does not.

The PsExec rule is the clearest example. The sample it is tested against has the
service renamed, so every rule looking for the string `PSEXESVC` finds nothing
in it. This one matches anyway, because it looks at the named pipes the program
has to create to carry the output of the command it runs, and those are built
from a pattern inside the program rather than from its file name.

Validate rule syntax:

```
sigma check rules/
```

## Tests

```
go test ./...
```

Every rule has a manifest in `tests/` stating which samples it must match and
how many times. The harness asserts the per-sample counts **and** the
repository-wide total, because a rule that starts firing on something new is as
much of a regression as one that stops firing — usually a broken exclusion
filter, which a positive-only test would never catch.

A manifest may also declare a **negative control**: the harness rewrites the
rule with every exclusion neutralised and requires it to match something.
Without that, a rule that can never fire looks exactly like a rule that
correctly finds nothing. The check exists because of a real bug here, where a
rule compared `Image` against a bare file name when the field holds a full path.
It could not have fired under any circumstances, and it reported zero either
way.

The manifests are also what keeps the engine in this repository honest. They
record what the reference engines found: which rule, in which file, how many
times. So one test runs Rastro's own engine over the same evidence and compares,
**per rule and per file** — not per total, because a rule that fires the right
number of times in the wrong places is wrong and a total would hide it. Both
halves are covered, each against the engine its manifests came from, and both
directions are checked: the files a manifest lists have to match, and the files
it does not list have to be empty.

Two more tests are the audit. One reads the whole corpus and fails on a single
unreadable record, because three times during this project a change made records
unreadable in bulk and the output was a confident number with nothing in it to
say what was missing. The other is narrower: a provider that **has** a
normalisation table must have a complete one. An empty gap list is not the bar —
the corpus holds an ESENT database, a SQL Server and an RPC trace that nobody
has described, and describing them would be weeks of work for events no rule
touches. A field of Sysmon or of the Security channel arriving in a shape its
table does not cover is different: it means the description is wrong, and a rule
written against that field is matching something other than what its author
believed.

The coverage of the rule loader against the public corpus is a test too:

```
git clone --depth 1 https://github.com/SigmaHQ/sigma tools/sigmahq
go test ./internal/sigma/ -run Corpus -v
```

`RASTRO_REQUIRE_TOOLS=1` turns a missing corpus or binary into a failure instead
of a skip. A developer without the evidence sees skips; CI, which fetches both
corpora at pinned commits, sees failures — because a broken setup that reports
success by running nothing at all is the worst outcome a test suite can have.

Two external engines are needed to build those expectations, because no single
one reads every kind of evidence: Hayabusa for the Windows rules and EVTX,
Zircolite for the Linux rules and auditd. Each manifest names the engine it
needs. Rastro itself needs neither to run.

Neither evidence set is copied into this repository. The Windows samples are
cloned at a pinned commit; the Linux ones are fetched file by file, because
upstream keeps them in Git LFS and a plain clone brings down pointer files
instead of data. `tests/linux-samples.txt` is the full list of what the Linux
rules are tested against.

`tests/README.md` covers the setup for both engines.

## The probe

`cmd/rastro-spike` came before any of this, to verify that Go could read
Windows event logs at all before an engine was built on that assumption. It is
kept because of what it found: the Go type of Sysmon's `GrantedAccess` field is
not stable across versions of the EVTX parser — `uint32` in one release, a named
`HexInt` type in another. Anything consuming it has to normalise, or rules
matching `'0x1010'` fail silently against the value `4112`.

That finding is why `internal/normalise` exists, and ignoring the second half of
it cost a full run: a type switch on `uint64` does not match a named type whose
underlying type is `uint64`, and every record in the corpus came out unreadable
with nothing in the output to say why. Both packages now use reflection, and
both have a regression test that declares its own named integer type.

## Author

Manuel Araújo — [LinkedIn](https://www.linkedin.com/in/manuel-ara%C3%BAjo-ba%C3%B1o-87955a150)
