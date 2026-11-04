# Rastro

[![CI](https://github.com/manu222/Rastro/actions/workflows/ci.yml/badge.svg)](https://github.com/manu222/Rastro/actions/workflows/ci.yml)

Forensic triage tool: give it the evidence from an incident — packet captures,
Windows event logs, system logs — and it returns a single correlated timeline
mapped to MITRE ATT&CK, in a report that reads equally well for a junior analyst
and for the person who has to make the call.

> **Status: early development.** The repository holds the detection rule
> library, the test harness that proves every rule still fires, and a
> feasibility probe for reading Windows event logs. The engine does not exist
> yet. This notice will be updated as that changes.

## Why

Every evidence source already has a good tool, and they all work well on their
own: Zeek for network traffic, Hayabusa for Windows events. What none of them do
is cross-reference each other. Working out that the DNS lookup at 14:02 and the
process creation at 14:03 belong to the same incident is done today by a person,
by hand, with several windows open.

Rastro does not reimplement those tools. It contributes the part that is missing:
correlation across sources, and the story that comes out of it.

## What is here today

| Path | Contents |
| --- | --- |
| `rules/windows/` | Sigma rules for Windows and Sysmon telemetry |
| `rules/linux/` | Sigma rules for auditd |
| `tests/` | One manifest per rule: which samples it must match, and how many times |
| `templates/` | A rule skeleton per telemetry source, carrying the real field names |
| `internal/ruletest/` | The harness that runs every rule against its manifest |
| `cmd/rastro-spike/` | Feasibility probe: reads an EVTX file and prints its events |
| `tools/`, `datasets/`, `datasets-linux/` | External tools and public evidence, not versioned |

## Coverage

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

### What it does not cover

Detection and noise are the same dial. Turning it up until nothing is missed
produces so many false alerts that nobody reads them, at which point attacks go
unnoticed again — by design this time. So the promise here is not completeness.
It is that the gaps are written down:

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
- **auditd records written as `unit= auditd`**, with a space after the equals
  sign, produce no `unit` field at all, so three of the eight events in one
  sample are invisible to the rule that looks for stopped services. A detection
  pipeline is only as good as the parser underneath it.

Each of these also lives in the rule or the manifest it belongs to, not only
here.

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

Two engines are needed, because no single one reads every kind of evidence:
Hayabusa for the Windows rules and EVTX, Zircolite for the Linux rules and
auditd. Each manifest names the engine it needs.

Neither evidence set is copied into this repository. The Windows samples are
cloned at a pinned commit; the Linux ones are fetched file by file, because
upstream keeps them in Git LFS and a plain clone brings down pointer files
instead of data. `tests/linux-samples.txt` is the full list of what the Linux
rules are tested against.

```
go test ./...
```

`tests/README.md` covers the setup for both engines.

## The probe

`cmd/rastro-spike` exists to verify that Go can read Windows event logs before
the engine is built on that assumption. Build and run:

```
go build -o rastro-spike.exe ./cmd/rastro-spike
.\rastro-spike.exe "datasets\Credential Access\sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"
```

It surfaced one finding worth recording: the Go type of Sysmon's `GrantedAccess`
field is not stable across versions of the EVTX parser — `uint32` in one release,
a named `HexInt` type in another. Anything consuming it has to normalise, or
rules matching `'0x1010'` fail silently against the value `4112`. See
`cmd/rastro-spike/hex.go`.

## Author

Manuel Araújo — [LinkedIn](https://www.linkedin.com/in/manuel-ara%C3%BAjo-ba%C3%B1o-87955a150)
