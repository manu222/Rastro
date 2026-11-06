package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manu222/rastro/internal/report"
)

// The ticket an analyst would be handed on day 1 of the APT29 evaluation, and
// the answers the report has to give, checked against MITRE's emulation plan
// for that day. docs/ticket-apt29.md is the same thing written for a person:
// the ticket, the questions, where the report answers each one and what the
// plan says happened.
//
// The ticket: an EDR alert, LSASS opened with full rights on SCRANTON a little
// after 03:05 UTC on 2 May 2020. Nothing else.
func TestTheAPT29DayOneTicket(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	day := filepath.Join(root, "datasets-apt29", "day1")
	if _, err := os.Stat(filepath.Join(day, "host", "host.json.gz")); err != nil {
		skipOrFailHere(t, "datasets-apt29/day1 is not on this machine (scripts/fetch-apt29.sh)")
		return
	}
	in, matches, _, err := analyse(filepath.Join(root, "rules"), day)
	if err != nil {
		t.Fatal(err)
	}
	r := report.Build(in, matches)

	if r.Limits.UnreadableRecords != 0 {
		t.Errorf("%d records could not be read; the answers below are over part of the evidence", r.Limits.UnreadableRecords)
	}

	// The alert itself, and the process behind it.
	var alert *report.Finding
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.RuleID == "3f2b9c14-7a5d-4e88-b0c3-9d1e6f4a2b77" && f.Host == "SCRANTON.dmevals.local" && reason(f, "GrantedAccess") == "0x1f3fff" {
			alert = f
			break
		}
	}
	if alert == nil {
		t.Fatal("no LSASS finding on SCRANTON with 0x1f3fff: the ticket cannot be opened from this report")
	}
	if n := len(alert.Lineage); n == 0 || !strings.HasSuffix(strings.ToLower(alert.Lineage[n-1].Image), `\powershell.exe`) {
		t.Errorf("the process that opened LSASS is not powershell.exe: %+v", alert.Lineage)
	}

	// Who. Sysmon 10 names no account; the report has to find it through the
	// process creation and say that it did.
	if alert.Account != `DMEVALS\pbeesly` || !alert.AccountDeduced || !strings.Contains(alert.AccountWhy, "ProcessGuid") {
		t.Errorf("account %q, deduced %v, why %q; want DMEVALS\\pbeesly, deduced through the ProcessGuid",
			alert.Account, alert.AccountDeduced, alert.AccountWhy)
	}

	// How it got in. In the plan, pbeesly runs a screensaver dropped in
	// C:\ProgramData\victim\ whose name hides its extension behind U+202E.
	if len(alert.Lineage) == 0 {
		t.Fatal("no lineage")
	}
	first := alert.Lineage[0]
	if !strings.HasPrefix(first.Image, `C:\ProgramData\victim\`) || !strings.HasSuffix(first.Image, "cod.3aka3.scr") ||
		first.Integrity != "Medium" || first.Account != `DMEVALS\pbeesly` {
		t.Errorf("the chain does not start at the screensaver, run by pbeesly at Medium: %+v", first)
	}
	// And the first call home: the first stage talks to 192.168.0.5 on
	// 1234, a different port from the 443 the later stage uses.
	if len(first.Opened) != 1 || first.Opened[0] != "192.168.0.5:1234 over tcp" {
		t.Errorf("the screensaver's connection is not on its step: %v", first.Opened)
	}

	// Elevation through sdclt.exe. The chain has to show it
	// and show the integrity level change across it.
	sawSdclt, before, after := false, "", ""
	for _, s := range alert.Lineage {
		if strings.HasSuffix(strings.ToLower(s.Image), `\sdclt.exe`) {
			sawSdclt, after = true, s.Integrity
			continue
		}
		if !sawSdclt {
			before = s.Integrity
		}
	}
	if !sawSdclt || before != "Medium" || after != "High" {
		t.Errorf("sdclt.exe in the chain %v, integrity %q before and %q at it; want Medium then High", sawSdclt, before, after)
	}

	// Where it talks. powershell.exe opened connections to 192.168.0.5:443,
	// and the network half of day 1 is another run, so none of them can have
	// been seen on the wire. A match here would be a join made on something
	// other than the five-tuple.
	if alert.Network == nil || alert.Network.Opened == 0 {
		t.Fatal("the acting process is not shown opening any connection")
	}
	for _, c := range alert.Network.Connections {
		if c.Remote != "192.168.0.5:443" {
			t.Errorf("a connection to %s; the plan's C2 is 192.168.0.5", c.Remote)
		}
	}
	if alert.Network.SeenOnWire != 0 {
		t.Errorf("%d of the acting process's connections were matched on the wire, and the wire is from another run", alert.Network.SeenOnWire)
	}

	// Where it went next. The plan moves to NASHUA: over WinRM, which shows as
	// wsmprovhost.exe reading LSASS under a network logon of pbeesly, and with
	// PsExec, whose pipes name the machine they came from.
	winrm, psexec := false, 0
	for _, f := range r.Findings {
		if f.Host != "NASHUA.dmevals.local" {
			continue
		}
		if f.RuleID == alert.RuleID && len(f.Lineage) > 0 && strings.HasSuffix(strings.ToLower(f.Lineage[0].Image), `\wsmprovhost.exe`) &&
			f.Entry != nil && f.Entry.TypeName == "network" && strings.HasSuffix(f.Entry.Account, `\pbeesly`) {
			winrm = true
		}
		if strings.HasPrefix(reason(&f, "PipeName"), `\PSEXESVC-SCRANTON-`) {
			psexec++
		}
	}
	if !winrm {
		t.Error("no LSASS read on NASHUA by wsmprovhost.exe under a network logon of pbeesly")
	}
	if psexec == 0 {
		t.Error("no PsExec pipe on NASHUA naming SCRANTON")
	}

	// What stays. The plan installs javamtsup.exe as a service; after
	// the reboot it is the parent of a bare rundll32.exe.
	persisted := false
	for _, f := range r.Findings {
		if f.Host != "SCRANTON.dmevals.local" || reason(&f, "CommandLine") != "rundll32.exe" {
			continue
		}
		for i, s := range f.Lineage {
			if strings.HasSuffix(strings.ToLower(s.Image), `\javamtsup.exe`) && i > 0 &&
				strings.HasSuffix(strings.ToLower(f.Lineage[i-1].Image), `\services.exe`) {
				persisted = true
			}
		}
	}
	if !persisted {
		t.Error("no rundll32.exe under javamtsup.exe under services.exe on SCRANTON")
	}

	// The executable on the wire. Zeek's PE analyser says what it was; no host
	// record of this evidence opened that connection, and the report says so
	// rather than leaving the process blank.
	pe := false
	for _, f := range r.Findings {
		if f.RuleID != "cb35f4a7-21bb-4c73-a5ce-7b582caf53ad" {
			continue
		}
		pe = true
		if f.Executable == nil || f.Executable.Machine != "AMD64" || !strings.Contains(f.Executable.Why, "pe.log") {
			t.Errorf("the file finding does not carry the PE analysis: %+v", f.Executable)
		}
		if f.Other == nil || !strings.Contains(f.Other.Unresolved, "no host record") || !strings.Contains(f.Other.Unresolved, "C1OVTv1ML8aw5ffxn6") {
			t.Errorf("the missing process is not explained through the uid: %+v", f.Other)
		}
	}
	if !pe {
		t.Error("the executable Zeek saw over HTTP is not a finding")
	}

	// And what the report cannot know: day 1's sensor wrote no capture_loss.log.
	said := false
	for _, n := range r.Limits.Notes {
		if strings.Contains(n, "no capture_loss.log") {
			said = true
		}
	}
	if !said {
		t.Error("the report does not say that the capture's completeness is unknown")
	}
}

func reason(f *report.Finding, field string) string {
	for _, w := range f.Why {
		if w.Field == field {
			return w.Value
		}
	}
	return ""
}
