package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Sysmon 5 out of LSASS_campaign_01, without its Message: UtcTime says
// 04:54 on the 16th, the record says 09:54 on the 15th.
const shippedTermination = `{"SourceName":"Microsoft-Windows-Sysmon","ProviderGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","Level":"4","Keywords":"0x8000000000000000","Channel":"Microsoft-Windows-Sysmon/Operational","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:54:06.400Z","@timestamp":"2023-08-15T09:54:06.400Z","EventID":5,"Task":"5","RuleName":"-","UtcTime":"2023-08-16 04:54:06.383","ProcessGuid":"{81056205-566b-64dc-2c04-000000000800}","ProcessId":"6252","Image":"C:\\Windows\\System32\\CompPkgSrv.exe","User":"PANDALAB\\stevie.marie"}`

// The same record with a LogonId planted in base ten. The corpus has no real
// one left once the provider tables are right, and this is the shape the
// audit exists for: Sysmon writes LogonId as 0x3e7, never as 999.
var shippedRewritten = strings.Replace(shippedTermination, `"RuleName":"-"`, `"RuleName":"-","LogonId":"999"`, 1)

// Both numbers the shipped-evidence reader measures reach report.Input. They
// used to be computed and dropped on the floor between the reader and the
// report, which no renderer test can see.
func TestTheShippedReaderNumbersReachTheReport(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	dir := t.TempDir()
	body := shippedTermination + "\n" + shippedRewritten + "\n"
	if err := os.WriteFile(filepath.Join(dir, "host.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	in, _, _, err := analyse(filepath.Join(root, "rules"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if in.ShippedRecords != 2 || in.ClockDisagreements != 2 {
		t.Errorf("shipped %d, disagreeing %d; want 2 and 2", in.ShippedRecords, in.ClockDisagreements)
	}
	if !strings.Contains(in.FirstClockDisagreement, "host.json") {
		t.Errorf("the first disagreement does not say where it was: %q", in.FirstClockDisagreement)
	}
	if len(in.ShipperForms) != 1 || in.ShipperForms[0].Field != "LogonId" || in.ShipperForms[0].Sample != "999" {
		t.Errorf("shipper forms: %+v", in.ShipperForms)
	}
}

// The application/x-dosexec row of LSASS_campaign_01's files.log and the pe.log
// row for the same file, with their headers, unchanged.
const (
	filesLog = "#fields\tts\tfuid\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tsource\tdepth\tanalyzers\tmime_type\tfilename\tduration\tlocal_orig\tis_orig\tseen_bytes\ttotal_bytes\tmissing_bytes\toverflow_bytes\ttimedout\tparent_fuid\tmd5\tsha1\tsha256\textracted\textracted_cutoff\textracted_size\n" +
		"1692161648.333854\tFmHWcO2PF9wbqM6cil\tCwSLisOv4lXMZlXd3\t192.168.1.41\t51126\t10.0.5.13\t80\tHTTP\t0\tPE\tapplication/x-dosexec\t-\t0.001217\tT\tF\t7168\t7168\t0\t0\tF\t-\t-\t-\t-\t-\t-\t-\n"
	peLog = "#fields\tts\tid\tmachine\tcompile_ts\tos\tsubsystem\tis_exe\tis_64bit\tuses_aslr\tuses_dep\tuses_code_integrity\tuses_seh\thas_import_table\thas_export_table\thas_cert_table\thas_debug_data\tsection_names\n" +
		"1692161648.333856\tFmHWcO2PF9wbqM6cil\tAMD64\t1271282813.000000\tWindows 95 or NT 4.0\tWINDOWS_GUI\tT\tT\tF\tF\tF\tT\tT\tF\tF\tF\t.text,.rdata,.cmcq\n"
)

// The PE analysis reaches the finding through analyse(), which no correlate or
// renderer test can see.
func TestAFileFindingCarriesThePEAnalysisThroughAnalyse(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"files.log": filesLog, "pe.log": peLog} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, matches, _, err := analyse(filepath.Join(root, "rules"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("%d findings; want the one PE rule hit", len(matches))
	}
	if x := matches[0].Exe.Exe; x == nil || x.Machine != "AMD64" {
		t.Errorf("the finding does not carry the PE analysis: %+v", matches[0].Exe)
	}
}

// An EXECVE whose SYSCALL is not in the evidence says so in the report, because
// every rule asking for Image is blind to it. The line is the pinned corpus's,
// from datasets-linux, unchanged.
func TestAnExecveWithNoSyscallIsDeclaredInTheReport(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	dir := t.TempDir()
	line := `type=EXECVE msg=audit(1723044684.257:15795): argc=3 a0="sudo" a1="LD_PRELOAD=./myfopen.so" a2="./prog"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _, _, err := analyse(filepath.Join(root, "rules"), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range in.Notes {
		if strings.HasPrefix(n, "1 audit EXECVE") {
			return
		}
	}
	t.Errorf("no note about the EXECVE without its SYSCALL: %q", in.Notes)
}

// A case assembled as links to each day's collection, the way an incident that
// spans days arrives. The linked day has to be read, a link that leads nowhere
// has to be declared, and a link back to the case has to end. Before this, the
// two days of APT29 linked into one folder read 0 records with exit code 0.
func TestALinkedDayIsReadAndABrokenLinkIsDeclared(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	base := t.TempDir()
	day := filepath.Join(base, "day1")
	caseDir := filepath.Join(base, "case")
	for _, d := range []string{day, caseDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(day, "host.json"), []byte(shippedTermination+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"day1": day, "gone": filepath.Join(base, "nowhere"), "loop": caseDir} {
		if err := os.Symlink(target, filepath.Join(caseDir, link)); err != nil {
			t.Skipf("symbolic links are not available here: %v", err)
		}
	}

	in, _, _, err := analyse(filepath.Join(root, "rules"), caseDir)
	if err != nil {
		t.Fatal(err)
	}
	if in.Records != 1 {
		t.Errorf("records read through the link: %d, want 1", in.Records)
	}
	declared := false
	for _, n := range in.Notes {
		if strings.HasPrefix(n, "1 link(s)") && strings.Contains(n, "gone") {
			declared = true
		}
	}
	if !declared {
		t.Errorf("the broken link was not declared: %q", in.Notes)
	}
}

// Two rows of day 2 of the APT29 evaluation's capture_loss.log, as the sensor
// wrote them, and the conn.log row that makes the directory network evidence.
const (
	captureLossRows = `{"@stream":"capture_loss","@system":"test-nsm","@proc":"zeek","ts":1588317555.874701,"ts_delta":936.0768949985504,"peer":"zeek","gaps":9,"acks":1195,"percent_lost":0.7531380753138075}` + "\n" +
		`{"@stream":"capture_loss","@system":"test-nsm","@proc":"zeek","ts":1588318370.510831,"ts_delta":814.6361300945282,"peer":"zeek","gaps":2,"acks":945,"percent_lost":0.21164021164021163}` + "\n"
	connRow = `{"@stream":"conn","@system":"test-nsm","@proc":"zeek","ts":1588316975.913849,"uid":"CpInR124KhH6PdwVqf","id_orig_h":"10.0.1.4","id_orig_p":63472,"id_resp_h":"10.0.0.4","id_resp_p":53,"proto":"udp","service":"dns","conn_state":"SF"}` + "\n"
)

// What the sensor says it missed reaches the report, and network evidence
// without that file says its completeness is unknown. capture_loss.log was
// skipped as a sensor diagnostic before, so a capture that lost a third of the
// traffic read exactly like one that lost none.
func TestTheSensorsOwnLossReachesTheReport(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	note := func(files map[string]string) string {
		dir := t.TempDir()
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		in, _, _, err := analyse(filepath.Join(root, "rules"), dir)
		if err != nil {
			t.Fatal(err)
		}
		if in.UnreadableRecords != 0 {
			t.Errorf("%d unreadable records", in.UnreadableRecords)
		}
		for _, n := range in.Notes {
			if strings.Contains(n, "capture_loss") {
				return n
			}
		}
		return ""
	}
	got := note(map[string]string{"conn.log": connRow, "capture_loss.log": captureLossRows})
	for _, want := range []string{"missing 11 of 2140", "2 interval(s)", "9 of 1195", "capture_loss.log line 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("the loss note does not say %q: %q", want, got)
		}
	}
	if got := note(map[string]string{"conn.log": connRow}); !strings.Contains(got, "unknown") {
		t.Errorf("network evidence without capture_loss.log is not called unknown: %q", got)
	}
}

// A logon id reused for a different account reaches the report's notes. The
// note was appended during the first pass and then overwritten by the notes
// every report carries, so the count in correlate was never seen.
func TestALogonConflictReachesTheReport(t *testing.T) {
	root, err := repoRootForTest()
	if err != nil {
		t.Skip("cannot find the repository root")
	}
	logon := func(user string) string {
		return `{"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security","Hostname":"SCRANTON.dmevals.local",` +
			`"TimeCreated":"2020-05-02T02:55:00.000Z","EventID":4624,"TargetUserName":"` + user +
			`","TargetDomainName":"DMEVALS","TargetLogonId":"0x3c4a1","LogonType":"2"}` + "\n"
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "host.json"), []byte(logon("pbeesly")+logon("mscott")), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _, _, err := analyse(filepath.Join(root, "rules"), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range in.Notes {
		if strings.HasPrefix(n, "1 logon id(s)") {
			return
		}
	}
	t.Errorf("no note about the reused logon id: %q", in.Notes)
}
