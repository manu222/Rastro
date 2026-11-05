# Rastro

[![CI](https://github.com/manu222/Rastro/actions/workflows/ci.yml/badge.svg)](https://github.com/manu222/Rastro/actions/workflows/ci.yml)

Forensic triage tool: give it the evidence from an incident — packet captures,
Windows event logs, system logs — and it returns a single correlated timeline
mapped to MITRE ATT&CK, in a report that reads equally well for a junior analyst
and for the person who has to make the call.

> **Status: the Windows half works end to end.** It reads an evidence directory
> of `.evtx` files, understands what the records mean, runs Sigma rules of its
> own against them and says what fired and why. What is missing is the
> correlation across sources, the report, and a reader for Linux audit logs.
> There is no network source yet.

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
Evaluations     : 127232  (4.1 rules per record on average)
Findings        : 45

  [HIGH] Windows Event Log Cleared
    2019-03-25 09:09:14  DC1.insecurebank.local  record 1 of ...
    audit log cleared by insecurebank\bob
    because Channel = Security  (rule asked for Security)
    because EventID = 1102  (rule asked for 1102)
```

Every number in that output is there because the alternative is a tool that
reports a confident zero. `0 unreadable` is a claim worth printing; so is
`1310 of 31243`, because "records read" and "records understood" are different
things and a report must not blur them.

## What is here

| Path | Contents |
| --- | --- |
| `cmd/rastro/` | The tool: `rastro read` and `rastro detect` |
| `internal/source/evtx/` | Reads Windows event logs, with per-file limits and a damaged-chunk count that never aborts a file |
| `internal/winevent/` | What a Windows record means: flattening, 46 mapped event ids, the translations |
| `internal/normalise/` | Restores the text a provider wrote when the parser changed its shape |
| `internal/event/` | The event model, including where each value came from |
| `internal/sigma/` | Rule loader and engine |
| `rules/windows/`, `rules/linux/` | The detection rules |
| `tests/` | One manifest per rule: which samples it must match, and how many times |
| `templates/` | A rule skeleton per telemetry source, carrying the real field names |
| `internal/ruletest/` | The harness that runs every rule against its manifest |
| `cmd/rastro-spike/` | The feasibility probe that came first, kept for what it found |
| `tools/`, `datasets/`, `datasets-linux/` | External tools and public evidence, not versioned |

## The rule engine

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

**13 rules, 11 ATT&CK techniques, 5 tactics.** Every one is executed against
public attack samples on each commit, and what is recorded is not a count but a
list: which sample file produces which hits.

| Technique | Rule | Platform | Hits |
| --- | --- | --- | --- |
| T1003.001 · LSASS Memory | LSASS memory access with read rights | Windows | 6 |
| T1003.001 · LSASS Memory | Process memory dumped through comsvcs.dll | Windows | 1 |
| T1003.006 · DCSync | Directory replication requested by a user account | Windows | 3 |
| T1036.005 · Match Legitimate Name or Location | services.exe executed from a non-standard path | Windows | 0 |
| T1053.003 · Cron | Scheduled task persistence through cron | Linux | 9 |
| T1218.011 · Rundll32 | rundll32.exe proxy execution | Windows | 12 |
| T1546.008 · Accessibility Features | Child process of a Windows accessibility tool | Windows | 2 |
| T1547.001 · Registry Run Keys | Autostart registry value set | Windows | 2 |
| T1569.002 · Service Execution | PsExec style service pipes | Windows | 6 |
| T1574.006 · Dynamic Linker Hijacking | LD_PRELOAD and /etc/ld.so.preload | Linux | 10 |
| T1685 · Disable or Modify Tools | UAC policy weakened via registry | Windows | 1 |
| T1685 · Disable or Modify Tools | Security service stopped | Linux | 21 |
| T1685.005 · Clear Windows Event Logs | Windows event log cleared | Windows | 12 |

Two techniques are covered by two rules each, which is why thirteen rules map to
eleven techniques. The services.exe rule matching nothing is not a mistake:
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
  abuses ages; the other half of that rule, which looks for rundll32 started
  with no arguments at all, does not depend on one.
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

- **auditd records written as `unit= auditd`**, with a space after the equals
  sign, produce no `unit` field at all, so three of the eight events in one
  sample are invisible to the rule that looks for stopped services. A detection
  pipeline is only as good as the parser underneath it.
- **Sysmon writes its WMI events with the values quoted and the backslashes
  doubled**: `Destination  "c:\\Windows\\System32\\cmd.exe"`. A rule matching a
  plain path against a Sysmon 19, 20 or 21 will never fire. Sysmon does that,
  not this tool, and it is the same class of silent failure the project started
  from.
- **Ten of Windows' message-table codes are shown as written.** `%%1833` and
  nine others were resolved by making a real installation render the records
  that carry them; the rest — audit policy categories, mostly — stay as
  `%%7688` until they can be checked the same way. Two of them Windows itself
  declined to resolve. An untranslated code is a gap the reader can look up; a
  wrong label is one they cannot catch.
- **No reader for Linux audit logs yet**, so the three auditd rules load, run
  and report nothing. They show up as loaded and silent, which is the honest
  way to say it.

Each of these also lives in the rule, the manifest or the code it belongs to,
not only here.

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
record what Hayabusa found: which rule, in which file, how many times. So one
test runs Rastro's own engine over the same evidence and compares, **per rule
and per file** — not per total, because a rule that fires the right number of
times in the wrong places is wrong and a total would hide it. Both directions
are checked: the files a manifest lists have to match, and the files it does not
list have to be empty.

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
