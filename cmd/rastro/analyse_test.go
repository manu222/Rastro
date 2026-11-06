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
