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
