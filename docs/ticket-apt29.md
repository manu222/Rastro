# A ticket, worked: day 1 of the APT29 evaluation

This is the test that asks whether the report is useful, as opposed to correct.
Every other test checks that a rule fires or a field lands where it should. This
one hands the tool what an analyst gets on a real shift, one alert and a folder
of evidence, and checks that the report answers the questions the analyst has to
answer before closing it.

The evidence is OTRF's recording of MITRE's ATT&CK evaluation emulating APT29
(`tests/apt29-samples.txt`, fetched by `scripts/fetch-apt29.sh`). The ground
truth is MITRE's published emulation plan for day 1:
<https://attackevals.github.io/ael/enterprise/apt29/archive/emulation_plan/day-1>.
The automated version is `TestTheAPT29DayOneTicket` in `cmd/rastro/ticket_test.go`,
and CI runs it with the corpus required.

## The ticket

> EDR alert, high: a process opened `lsass.exe` with full access on
> `SCRANTON.dmevals.local`, 2 May 2020, shortly after 03:05 UTC.

That is all. No user, no process name, no idea how long the attacker has been
there.

```
rastro report -out ticket.md datasets-apt29/day1
```

198,221 records, 27 files, 32 findings, about 20 seconds on a two-vCPU container.

## The questions, and where the report answers them

| Question | Where it is in the report | What the report says | What the plan says |
|---|---|---|---|
| Which machine? | the finding's host | `SCRANTON.dmevals.local` | SCRANTON is the first victim |
| Which account? | the finding's account, marked deduced | `DMEVALS\pbeesly`, through the process creation with the same ProcessGuid | the user who opens the lure |
| What opened LSASS? | last step of "How it got there" | `powershell.exe` at High integrity, `GrantedAccess 0x1f3fff` | credential theft from PowerShell |
| How did it get in? | first step of the chain | `C:\ProgramData\victim\‮cod.3aka3.scr /S`, run by pbeesly at Medium | a screensaver whose name hides its extension behind U+202E |
| Did it escalate? | the chain | Medium up to `cmd.exe`, High from `sdclt.exe` on | UAC bypass through sdclt |
| Where does it talk? | the steps' connections, and the network section of the finding | the screensaver to `192.168.0.5:1234`, PowerShell to `192.168.0.5:443` | the C2 server is 192.168.0.5 |
| Did it move? | findings on NASHUA | `wsmprovhost.exe` reading LSASS under a network logon of pbeesly; PsExec pipes named `PSEXESVC-SCRANTON-*` | WinRM and PsExec to NASHUA |
| Will it come back? | `rundll32.exe Started With No Arguments` | `services.exe` → `javamtsup.exe` → `rundll32.exe`, after a reboot | a service called javamtsup |
| Did anything cross the wire? | `Windows Executable Transferred Over Cleartext HTTP` | a 64-bit Windows console executable from 192.168.0.4, analysed by Zeek's pe.log | not checked: the wire is another run (below) |

Every row is asserted by the test, field by field, not by searching the text.

## What the report gets wrong, and what it cannot know

**One false positive.** `Autostart Registry Value Set` fires on
`HKLM\...\Run\WindowsDefender`, written by `MsMpEng.exe`. That is Defender
registering itself. The rule has no exclusion for it, and adding one is a
decision for whoever runs the rule, not for the tool.

**No network attribution, correctly.** The host and the network halves of day 1
are two different runs of the plan. The Zeek logs cover 00:06 to 00:45 UTC on
30 April; Sysmon runs from 02:55 to 03:28 UTC on 2 May. None of the connections
PowerShell opened appears on the wire, and the report says "the network
evidence does not hold" for each one. The PE that crossed the wire is reported
with "no host record in this evidence names a process for 10.0.1.4:60802 to
192.168.0.4:80". A tool that joined on addresses, or on time with a tolerance,
would have attributed that download to whatever SCRANTON process was talking to
192.168.0.4 two days later. The test fails if any connection of the acting
process is matched on the wire.

The same corpus is why fixed client ports are no longer joined. NTP (123 to 123)
and NetBIOS (137, 138) repeat the same five-tuple on every exchange, and the only
two unique joins day 1 produced were NetBIOS packets matched across those two
days.

**The capture's completeness is unknown.** Day 1's sensor wrote no
`capture_loss.log`, and the report says so instead of implying the capture was
whole. Day 2's sensors did: they missed 11 of 2,452 acknowledged segments.

**The name of the first-stage file arrives mangled.** The shipper encoded U+202E
twice, so the path reads `C:\ProgramData\victim\â€®cod.3aka3.scr`. The report
shows it as it arrived. Repairing it would mean guessing which bytes were meant.

**What the plan does that no rule here sees.** Collection, staging and
exfiltration leave no finding: the repository's fifteen rules do not cover
them. A SOC running its own rules over the same evidence would see more, and the
report's "silent rules" list says which of the loaded rules found nothing.

## Scoring a run

Count a question as answered when the report gives the plan's answer with its
provenance (the record it came from, and the reason when it is deduced). Count
it as wrong when the report gives a different answer, and as unanswered when the
report says it does not know. Unanswered is not a failure; a wrong answer is.

The current run: eight of eight answered, the ninth row left unscored, one false positive, no wrong answers.
