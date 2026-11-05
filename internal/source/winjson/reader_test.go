package winjson

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/normalise"
	"github.com/manu222/rastro/internal/sigma"
)

// Every line below was copied out of the compound corpus, untouched. The whole
// question this reader answers is whether somebody else's rendering of a
// Windows record can still be matched by a rule written for the record, and a
// line this reader has to understand is one a shipper actually wrote.
//
// The Message field is kept in the constants even though it is most of their
// length, because it is most of the file's length too and dropping it here
// would be testing a tidier format than the one that exists.

// A Sysmon process creation. Note the two integers: ProcessId is 7448 and
// LogonId is 0x62f2d, in the same record, which is the split the provider
// tables describe and the reason this reader checks them.
const sysmonCreate = `{"SourceName":"Microsoft-Windows-Sysmon","ProviderGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","Level":"4","Keywords":"0x8000000000000000","Channel":"Microsoft-Windows-Sysmon/Operational","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:53:48.554Z","@timestamp":"2023-08-15T09:53:48.554Z","EventID":1,"Message":"Process Create:","Task":"1","RuleName":"-","UtcTime":"2023-08-16 04:53:48.446","ProcessGuid":"{81056205-565c-64dc-2304-000000000800}","ProcessId":"7448","Image":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","FileVersion":"92.0.902.67","Description":"Microsoft Edge","Product":"Microsoft Edge","Company":"Microsoft Corporation","OriginalFileName":"msedge.exe","CommandLine":"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default","CurrentDirectory":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\","User":"PANDALAB\\stevie.marie","LogonGuid":"{81056205-d113-64d4-2d2f-060000000000}","LogonId":"0x62f2d","TerminalSessionId":"1","IntegrityLevel":"Medium","Hashes":"SHA1=FA9E8B7FB10473A01B8925C4C5B0888924A1147C,MD5=AD8536C7440638D40156E883AC25086E,SHA256=73D84D249F16B943D1D3F9DD9E516FADD323E70939C29B4A640693EB8818EE9A,IMPHASH=3A3DE7172D7A4E00C1867DD2F13AD959","ParentProcessGuid":"{81056205-d124-64d4-6a00-000000000800}","ParentProcessId":"4544","ParentImage":"C:\\Windows\\explorer.exe","ParentCommandLine":"C:\\Windows\\Explorer.EXE","ParentUser":"PANDALAB\\stevie.marie"}`

// A Sysmon network connection out of the same file. Its UtcTime says the tenth
// of August and its record is dated the fifteenth, which is not a typo here: it
// is what the corpus contains, on this event type and on event 22 and on no
// other, and it is why the reader prefers the record's own time.
const sysmonConnect = `{"SourceName":"Microsoft-Windows-Sysmon","ProviderGuid":"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}","Level":"4","Keywords":"0x8000000000000000","Channel":"Microsoft-Windows-Sysmon/Operational","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:53:50.158Z","@timestamp":"2023-08-15T09:53:50.158Z","EventID":3,"Message":"Network connection detected:","Task":"3","RuleName":"-","UtcTime":"2023-08-10 14:39:12.046","ProcessGuid":"{81056205-d0f7-64d4-1b00-000000000800}","ProcessId":"1048","Image":"C:\\Windows\\System32\\svchost.exe","User":"NT AUTHORITY\\NETWORK SERVICE","Protocol":"udp","Initiated":"true","SourceIsIpv6":"false","SourceIp":"192.168.1.41","SourceHostname":"-","SourcePort":"63829","SourcePortName":"-","DestinationIsIpv6":"false","DestinationIp":"192.168.1.4","DestinationHostname":"-","DestinationPort":"53","DestinationPortName":"-"}`

// A Security process creation, where the same two kinds of integer are written
// the other way round: this provider writes its process ids in hexadecimal.
const securityCreate = `{"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"{54849625-5478-4994-a5ba-3e3b0328c30d}","Level":"0","Keywords":"0x8020000000000000","Channel":"Security","Hostname":"MKT01.pandalab.com","TimeCreated":"2023-08-15T09:53:48.447Z","@timestamp":"2023-08-15T09:53:48.447Z","EventID":4688,"Message":"A new process has been created.","Task":"13312","SubjectUserSid":"S-1-5-21-1939123204-1418869057-2368897034-1106","SubjectUserName":"stevie.marie","SubjectDomainName":"PANDALAB","SubjectLogonId":"0x62f2d","NewProcessId":"0x1d18","NewProcessName":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","TokenElevationType":"%%1936","ProcessId":"0x11c0","CommandLine":"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default","TargetUserSid":"S-1-0-0","TargetUserName":"-","TargetDomainName":"-","TargetLogonId":"0x0","ParentProcessName":"C:\\Windows\\explorer.exe","MandatoryLabel":"S-1-16-8192"}`

func read(t *testing.T, name, body string) (*Reader, []*event.Event, Stats) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)

	data := []byte(body)
	if strings.HasSuffix(name, ".gz") {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		data = buf.Bytes()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	r := New(dir)
	var out []*event.Event
	stats, err := r.ReadFile(path, func(e *event.Event) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, out, stats
}

func TestARealShippedProcessCreation(t *testing.T) {
	_, events, stats := read(t, "host.json", sysmonCreate+"\n")
	if stats.Records != 1 || stats.Unparsed != 0 || stats.Unreadable != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	e := events[0]

	// The fields exactly as the shipper wrote them. A rule asks for ProcessId
	// and for LogonId, and the two are written in different bases in the same
	// record: rendering either into something tidier breaks the rule.
	for field, want := range map[string]string{
		"ProcessId":      "7448",
		"LogonId":        "0x62f2d",
		"Image":          `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		"User":           `PANDALAB\stevie.marie`,
		"EventID":        "1",
		"IntegrityLevel": "Medium",
	} {
		if got := e.Raw[field]; got != want {
			t.Errorf("%s: want %q, got %q", field, want, got)
		}
	}

	if e.Origin.Product != "windows" || e.Origin.Service != "sysmon" {
		t.Errorf("a rule asking for windows/sysmon would not see this: %+v", e.Origin)
	}
	if e.Class != event.ClassProcess || e.Action != "process created" {
		t.Errorf("class %s action %q", e.Class, e.Action)
	}
	if e.Host.Value != "MKT01.pandalab.com" {
		t.Errorf("host: %+v", e.Host)
	}
	// The mapping that the EVTX path uses has to work here too, because it is
	// the same mapping: this is the one Sysmon event that names the user and
	// carries the logon session.
	if e.User.Value != `PANDALAB\stevie.marie` {
		t.Errorf("user: %+v", e.User)
	}
	if e.Process.PID.Value != "7448" || e.Parent.Image.Value != `C:\Windows\explorer.exe` {
		t.Errorf("process %+v parent %+v", e.Process, e.Parent)
	}

	// Four digests in one field, which a report has to be able to show as four
	// things somebody can look up rather than one two-hundred-character string.
	hashes := 0
	for _, ent := range e.Entities {
		if ent.Kind == event.KindHash {
			hashes++
		}
	}
	if hashes != 4 {
		t.Errorf("want the four digests as four entities, got %d", hashes)
	}
}

// The spellings a shipper flattens away. A rule is written against the names
// Windows' own XML uses, and without these the rule loads, runs and never fires
// on evidence that is in front of it.
func TestTheShipperSpellingsReachARuleWrittenForTheXML(t *testing.T) {
	_, events, _ := read(t, "host.json", securityCreate+"\n")
	e := events[0]

	for field, want := range map[string]string{
		"Computer":      "MKT01.pandalab.com",
		"Provider_Name": "Microsoft-Windows-Security-Auditing",
		"SystemTime":    "2023-08-15T09:53:48.447Z",
	} {
		if got := e.Raw[field]; got != want {
			t.Errorf("%s: want %q, got %q", field, want, got)
		}
	}
	// And the shipper's own name is still there. Nothing is renamed.
	if e.Raw["Hostname"] != "MKT01.pandalab.com" {
		t.Errorf("the shipper's own spelling was dropped: %v", e.Raw["Hostname"])
	}
}

// The time. This is the decision the reader makes differently from the EVTX
// reader, so it is the one that gets pinned down.
func TestTheRecordTimeIsUsedAndADisagreementIsCounted(t *testing.T) {
	_, events, stats := read(t, "host.json", sysmonConnect+"\n")
	e := events[0]

	if got := e.Time.Format("2006-01-02 15:04:05.000"); got != "2023-08-15 09:53:50.158" {
		t.Errorf("the event was dated %s, which is not when its record says it was written", got)
	}
	if e.Origin.TimeField != "TimeCreated" {
		t.Errorf("the timeline does not say which time it used: %q", e.Origin.TimeField)
	}
	// Five days apart, counted, with the first one kept in full.
	if stats.Disagreements != 1 {
		t.Errorf("a record whose two times are five days apart was not counted: %+v", stats)
	}
	if stats.FirstDisagreement == nil {
		t.Error("a disagreement was counted with nothing said about it")
	}
	// And the provider's own statement is still in the fields, untouched: a
	// rule matching UtcTime has to see what the provider wrote.
	if e.Raw["UtcTime"] != "2023-08-10 14:39:12.046" {
		t.Errorf("UtcTime was changed or dropped: %q", e.Raw["UtcTime"])
	}
}

// The same file, with the two times agreeing. Nothing should be counted, or the
// count means nothing.
func TestTimesThatAgreeAreNotCounted(t *testing.T) {
	body := strings.Replace(sysmonCreate, `"UtcTime":"2023-08-16 04:53:48.446"`,
		`"UtcTime":"2023-08-15 09:53:48.446"`, 1)
	_, _, stats := read(t, "host.json", body+"\n")
	if stats.Disagreements != 0 {
		t.Errorf("two times a few milliseconds apart were reported as a disagreement: %+v", stats)
	}
}

// The audit. A shipper that writes a hexadecimal field in base ten breaks every
// rule that mentions it, and the break is silent: the rule simply stops firing.
func TestAFieldWrittenInTheWrongBaseIsReported(t *testing.T) {
	// 0x1d18 is 7448. A shipper that wrote the decimal would look perfectly
	// reasonable and would stop every rule matching NewProcessId.
	body := strings.Replace(securityCreate, `"NewProcessId":"0x1d18"`, `"NewProcessId":"7448"`, 1)
	r, events, stats := read(t, "host.json", body+"\n")
	if stats.Records != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	// The record is still read. A field in an unexpected form is a reason to
	// flag the field, not to throw away the evidence.
	if events[0].Raw["NewProcessId"] != "7448" {
		t.Errorf("the value was changed instead of reported: %q", events[0].Raw["NewProcessId"])
	}

	found := false
	for _, d := range r.Divergences() {
		if d.Field != "NewProcessId" {
			continue
		}
		found = true
		if d.Declared != normalise.FormHex || d.Written != "decimal" {
			t.Errorf("reported as declared %s written %s", d.Declared, d.Written)
		}
		if d.Producer != "Microsoft-Windows-Security-Auditing" {
			t.Errorf("attributed to %q", d.Producer)
		}
	}
	if !found {
		t.Errorf("a hexadecimal field written in base ten was not reported: %+v", r.Divergences())
	}
}

// And the corpus as it actually is reports nothing, or the audit is crying wolf
// and whoever reads it will learn to ignore it.
func TestAFaithfulShipperIsReportedClean(t *testing.T) {
	r, _, stats := read(t, "host.json", sysmonCreate+"\n"+sysmonConnect+"\n"+securityCreate+"\n")
	if stats.Records != 3 {
		t.Fatalf("stats: %+v", stats)
	}
	if d := r.Divergences(); len(d) != 0 {
		t.Errorf("three records a shipper wrote faithfully were reported as divergent: %+v", d)
	}
}

// Zero is not evidence of a base. Reporting it would fill the audit with noise
// from every TargetLogonId of every record that has none.
func TestZeroIsNotReportedAsTheWrongBase(t *testing.T) {
	body := strings.Replace(securityCreate, `"TargetLogonId":"0x0"`, `"TargetLogonId":"0"`, 1)
	r, _, _ := read(t, "host.json", body+"\n")
	for _, d := range r.Divergences() {
		if d.Field == "TargetLogonId" {
			t.Errorf("a zero was reported as the wrong base: %+v", d)
		}
	}
}

// A line that is not a record is counted and the rest of the file is still
// read. Abandoning the file would throw away everything after one bad line,
// which is the failure this project spends its time avoiding.
func TestALineThatIsNotARecordIsCountedAndTheRestIsRead(t *testing.T) {
	body := sysmonCreate + "\n" + "this is not json at all\n" + securityCreate + "\n"
	_, events, stats := read(t, "host.json", body)

	if stats.Records != 2 || stats.Unparsed != 1 {
		t.Errorf("stats: %+v", stats)
	}
	if stats.FirstFailure == nil {
		t.Error("a line was not read and nothing says why")
	}
	if len(events) != 2 || events[1].Raw["EventID"] != "4688" {
		t.Errorf("the record after the bad line was not read: %d events", len(events))
	}
	// The line number is what sends somebody back to the evidence, so it has to
	// be the line in the file and not the count of records read.
	if !strings.Contains(stats.FirstFailure.Error(), "line 2") {
		t.Errorf("the cause does not say which line: %v", stats.FirstFailure)
	}
}

// A record with no event identifier cannot be matched by a rule and cannot be
// placed in the mapping, so it is counted rather than emitted as an event that
// claims to be event 0.
func TestARecordWithNoEventIdIsCounted(t *testing.T) {
	_, events, stats := read(t, "host.json", `{"SourceName":"Microsoft-Windows-Sysmon","Channel":"x"}`+"\n")
	if stats.Unreadable != 1 || stats.Records != 0 || len(events) != 0 {
		t.Errorf("stats: %+v, %d events", stats, len(events))
	}
	if stats.FirstFailure == nil {
		t.Error("a record was dropped and nothing says why")
	}
}

// Compressed and not have to produce the same events. The corpus is kept
// gzipped because a hundred megabytes of mostly one event type is not worth the
// disk, and that saving is only free if it changes nothing.
func TestGzippedAndPlainAgree(t *testing.T) {
	body := sysmonCreate + "\n" + sysmonConnect + "\n" + securityCreate + "\n"
	_, plain, plainStats := read(t, "host.json", body)
	_, zipped, zipStats := read(t, "host.json.gz", body)

	if plainStats.Records != zipStats.Records || plainStats.Disagreements != zipStats.Disagreements {
		t.Fatalf("plain %+v, gzipped %+v", plainStats, zipStats)
	}
	for i := range plain {
		if !plain[i].Time.Equal(zipped[i].Time) {
			t.Errorf("record %d: the two forms disagree about the time", i)
		}
		if len(plain[i].Raw) != len(zipped[i].Raw) {
			t.Errorf("record %d: %d fields plain, %d gzipped", i, len(plain[i].Raw), len(zipped[i].Raw))
		}
		for k, v := range plain[i].Raw {
			if zipped[i].Raw[k] != v {
				t.Errorf("record %d: %s differs between the two forms", i, k)
			}
		}
	}
}

// Both names, and nothing else. A .log in the same directory is an auditd or a
// Zeek log and belongs to another reader.
func TestHandles(t *testing.T) {
	for name, want := range map[string]bool{
		"host.json":    true,
		"host.json.gz": true,
		"HOST.JSON":    true,
		"conn.log":     false,
		"system.evtx":  false,
		"notes.txt":    false,
	} {
		if got := Handles(name); got != want {
			t.Errorf("%s: want %v, got %v", name, want, got)
		}
	}
}

// And the whole point: a rule written for Windows matches a record that reached
// the pipeline through a shipper, and a rule written for something else never
// sees it.
func TestAWindowsRuleMatchesAShippedRecord(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yml")
	if err := os.WriteFile(rulePath, []byte(`
title: Edge started from the shell
logsource:
    product: windows
    service: sysmon
detection:
    process_creation:
        EventID: 1
    selection:
        Image|endswith: '\msedge.exe'
        ParentImage|endswith: '\explorer.exe'
    condition: process_creation and selection
level: low
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := sigma.LoadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}

	_, events, _ := read(t, "host.json", sysmonCreate+"\n")
	e := events[0]
	if !c.Applies(e.Origin.Product, e.Origin.Service, e.Origin.Category) {
		t.Fatal("a Windows rule did not apply to a Windows record")
	}
	if !c.Matches(e.Raw) {
		t.Fatalf("the rule did not match: %v", e.Raw)
	}
	if hits := c.Explain(e.Raw); len(hits) != 3 {
		t.Errorf("want three reasons, got %+v", hits)
	}

	// The same record against a rule for another product.
	zeekRule := strings.Replace(`
title: Edge started from the shell
logsource:
    product: zeek
    service: dns
detection:
    selection:
        Image|endswith: '\msedge.exe'
    condition: selection
level: low
`, "\t", "    ", -1)
	zeekPath := filepath.Join(dir, "zeek.yml")
	if err := os.WriteFile(zeekPath, []byte(zeekRule), 0o600); err != nil {
		t.Fatal(err)
	}
	zc, err := sigma.LoadFile(zeekPath)
	if err != nil {
		t.Fatal(err)
	}
	if zc.Applies(e.Origin.Product, e.Origin.Service, e.Origin.Category) {
		t.Error("a Zeek rule was offered a Windows record")
	}
}

// A rule matching a logon id against the hexadecimal the provider writes. This
// is the test that fails if anything in this path starts helpfully converting
// numbers.
func TestARuleMatchingAHexadecimalLogonIdStillFires(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yml")
	if err := os.WriteFile(rulePath, []byte(`
title: A process in one particular logon session
logsource:
    product: windows
detection:
    selection:
        EventID: 1
        LogonId: '0x62f2d'
    condition: selection
level: low
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := sigma.LoadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	_, events, _ := read(t, "host.json", sysmonCreate+"\n")
	if !c.Matches(events[0].Raw) {
		t.Errorf("a rule matching 0x62f2d did not fire on a record carrying it: %q", events[0].Raw["LogonId"])
	}
}
