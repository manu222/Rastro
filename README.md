# Rastro

Forensic triage tool: give it the evidence from an incident — packet captures,
Windows event logs, system logs — and it returns a single correlated timeline
mapped to MITRE ATT&CK, in a report that reads equally well for a junior analyst
and for the person who has to make the call.

> **Status: early development.** The repository currently holds the detection
> rule library and a feasibility probe for reading Windows event logs. The engine
> does not exist yet. This notice will be updated as that changes.

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
| `rules/linux/` | Rules for auditd and sshd — pending |
| `tests/` | Log samples proving each rule fires |
| `cmd/rastro-spike/` | Feasibility probe: reads an EVTX file and prints its events |
| `tools/` | External tools, not versioned |
| `datasets/` | Public attack logs used for validation, not versioned |

## Detection rules

Rules follow the [Sigma](https://sigmahq.io) format and are validated against real
attack logs. The guiding principle is to detect **behaviour** rather than
artefacts: a rule keyed on a tool's filename stops working the moment an attacker
renames it, while a rule keyed on the access rights a technique requires does not.

Validate rule syntax:

```
sigma check rules/
```

Run the rules against an evidence set:

```
tools\hayabusa\hayabusa-4.0.0-win-x64.exe dfir-timeline -d datasets -r rules -o out.csv -w -s -q -C
```

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

## Coverage

Rastro does not detect every attack, because no system does: detection and noise
are the same dial, and turning it up until nothing is missed produces so many
false alerts that nobody reads them. What this project does instead is state
exactly what it covers, with the samples that prove it, and record its known
blind spots rather than hiding them.

## Author

Manuel Araújo — [LinkedIn](https://www.linkedin.com/in/manuel-ara%C3%BAjo-ba%C3%B1o-87955a150)
