package winevent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/manu222/rastro/internal/normalise"
)

// Every record under testdata/ was taken out of the pinned corpus, not written
// by hand. A fixture somebody invented proves that the code handles what its
// author imagined; these prove it handles what Windows actually writes.

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are kept as json.Number so that a large integer is not rounded
	// on its way through a float64 — the same reason the normaliser refuses
	// imprecise floats.
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return rec
}

func TestSysmonProcessCreation(t *testing.T) {
	f, err := Flatten(load(t, "sysmon_process_creation"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}

	// The two blocks end up in one namespace, which is what a rule assumes.
	for field, want := range map[string]string{
		"EventID":       "1",
		"Channel":       "Microsoft-Windows-Sysmon/Operational",
		"Computer":      "IEWIN7",
		"Provider_Name": "Microsoft-Windows-Sysmon",
	} {
		if got := f.Fields[field]; got != want {
			t.Errorf("%s: want %q, got %q", field, want, got)
		}
	}
	if f.Fields["Image"] == "" || f.Fields["CommandLine"] == "" {
		t.Errorf("EventData did not reach the flat view: %v", f.Fields)
	}
	if f.EventID != 1 {
		t.Errorf("EventID not parsed: %d", f.EventID)
	}
	if f.Time.IsZero() {
		t.Error("the record has a SystemTime and the event has no time")
	}
	if f.Time.Year() < 2015 || f.Time.Year() > 2030 {
		t.Errorf("implausible time parsed: %s", f.Time)
	}
}

// 378 records in the pinned corpus write EventID as an element with attributes
// rather than as a bare number. Taken literally that turns EventID into a
// structure, and every rule matching on it stops working — quietly, because a
// rule that matches nothing looks exactly like a rule with nothing to match.
func TestEventIDWrittenAsAnObject(t *testing.T) {
	f, err := Flatten(load(t, "eventid_as_object"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Fields["EventID"] != "3001" {
		t.Errorf("EventID: want 3001, got %q", f.Fields["EventID"])
	}
	if f.EventID != 3001 {
		t.Errorf("EventID not parsed: %d", f.EventID)
	}
	// The attribute that came with it is kept rather than thrown away.
	if f.Fields["EventID_Qualifiers"] != "16384" {
		t.Errorf("the Qualifiers attribute was lost: %v", f.Fields)
	}
	// This record also carries attributes on EventData itself.
	if f.Fields["EventData_Name"] != "EVENT_PROCESSTERMINATION_CROSSPROCESS" {
		t.Errorf("EventData attributes were lost: %v", f.Fields)
	}
}

// Sysmon's own service state record has a Version in both blocks: the schema
// version of the event, and the version of Sysmon. One name, two meanings.
func TestNameCollisionKeepsBothValues(t *testing.T) {
	f, err := Flatten(load(t, "version_collision"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Fields["Version"] != "9.01" {
		t.Errorf("EventData should win a collision: want 9.01, got %q", f.Fields["Version"])
	}
	if f.Shadowed["Version"] != "3" {
		t.Errorf("the displaced System value was dropped: %v", f.Shadowed)
	}
}

// Absent is not empty. A provider that writes no Channel must not come out of
// here with Channel set to "", because a rule testing for the field would then
// be comparing against something that was never recorded.
func TestMissingChannelStaysMissing(t *testing.T) {
	f, err := Flatten(load(t, "rpc_without_channel"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, present := f.Fields["Channel"]; present {
		t.Errorf("a Channel was produced for a record that has none: %q", f.Fields["Channel"])
	}
	// This provider registers no name, only a GUID, and that is then what
	// identifies it. Leaving the producer empty would merge it with every other
	// nameless source.
	if f.Producer != "{68fdd900-4a3e-11d1-84f4-0000f80464e3}" {
		t.Errorf("a provider known only by GUID was not identified: %q", f.Producer)
	}
}

// The DCSync rule reads Properties and SubjectUserName off a 4662. If either
// fails to arrive, rule 9 stops firing and its manifest goes red — this test
// says so three layers earlier, where the cause is obvious.
func TestSecurityRecordCarriesTheFieldsRule9Needs(t *testing.T) {
	f, err := Flatten(load(t, "security_4662"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.EventID != 4662 {
		t.Fatalf("EventID: %d", f.EventID)
	}
	if f.Fields["Properties"] == "" {
		t.Error("Properties is empty")
	}
	if f.Fields["SubjectUserName"] == "" {
		t.Error("SubjectUserName is empty")
	}
}

// Nothing in the corpus should reach the flattener as an undeclared, reshaped
// field without that being noticed. This is the audit in miniature: the real
// one runs over all 132 files once the reader exists.
func TestFixturesRaiseNoUndeclaredFields(t *testing.T) {
	n := normalise.Default()
	for _, name := range []string{
		"sysmon_process_creation", "version_collision", "security_4662",
	} {
		if _, err := Flatten(load(t, name), n); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if gaps := n.Gaps(); len(gaps) != 0 {
		t.Errorf("fields arrived in a shape nobody declared: %+v", gaps)
	}
}

// The Go EVTX parser this project uses does not produce the shape the fixtures
// above were captured in. It writes an element's own value under the key Value
// and lifts the attributes up beside it, and it decodes SystemTime into
// seconds since the Unix epoch rather than leaving the timestamp as text.
//
// This record is built to that shape rather than captured, because that parser
// cannot be run where these tests were written. It is derived from the
// library's own expansion code, and the first run of the reader against a real
// file is what confirms it — if this test is passing and the reader still
// produces nothing, this fixture is the first place to look.
func TestGoParserShape(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider":      map[string]any{"Name": "Microsoft-Windows-Sysmon", "Guid": "{5770385f}"},
				"EventID":       map[string]any{"Qualifiers": int64(0), "Value": int64(10)},
				"Channel":       "Microsoft-Windows-Sysmon/Operational",
				"Computer":      "MSEDGEWIN10",
				"EventRecordID": int64(306346),
				"TimeCreated":   map[string]any{"SystemTime": 1557670683.5895078},
				"Execution":     map[string]any{"ProcessID": int64(2036), "ThreadID": int64(296)},
			},
			"EventData": map[string]any{
				"SourceImage":   `C:\Users\Public\a.exe`,
				"TargetImage":   `C:\Windows\system32\lsass.exe`,
				"GrantedAccess": uint32(4112),
			},
		},
	}

	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.EventID != 10 {
		t.Errorf("EventID from the Value key: want 10, got %d", f.EventID)
	}
	if f.Producer != "Microsoft-Windows-Sysmon" {
		t.Errorf("provider from a flattened attribute: %q", f.Producer)
	}
	if f.Fields["ExecutionProcessID"] != "2036" {
		t.Errorf("attribute alias missing: %v", f.Fields)
	}
	// The finding from the feasibility probe, now end to end: a mask that
	// arrives as a number comes out as the text rule 1 matches against.
	if f.Fields["GrantedAccess"] != "0x1010" {
		t.Errorf("GrantedAccess: want 0x1010, got %q", f.Fields["GrantedAccess"])
	}
	if f.Time.IsZero() || f.Time.Year() != 2019 {
		t.Errorf("epoch seconds not decoded: %s", f.Time)
	}
}

// Sysmon writes two times: when the event happened, and when the record was
// written. They are not the same instant, and in this corpus they differ by up
// to 41 milliseconds — enough to reorder two events in a timeline. The
// provider's own account of when it happened wins.
func TestProviderTimeWinsOverRecordTime(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider":    map[string]any{"Name": "Microsoft-Windows-Sysmon"},
				"EventID":     map[string]any{"Value": int64(11)},
				"Computer":    "MSEDGEWIN10",
				"TimeCreated": map[string]any{"SystemTime": 1599826222.3987265},
			},
			"EventData": map[string]any{
				"UtcTime":         "2020-09-11 12:10:22.357",
				"CreationUtcTime": "2019-01-01 00:00:00.000",
				"TargetFilename":  `C:\Windows\System32\mimilsa.log`,
			},
		},
	}

	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.TimeSource != "UtcTime" {
		t.Errorf("the record's own write time was preferred: %q", f.TimeSource)
	}
	if got := f.Time.Format("2006-01-02 15:04:05.000"); got != "2020-09-11 12:10:22.357" {
		t.Errorf("want the provider's time, got %s", got)
	}
	// CreationUtcTime is a property of the file, not of the event. Reading it as
	// the event time would move the event to whenever somebody last touched
	// whatever it mentions.
	if f.Time.Year() == 2019 {
		t.Error("a file's creation time was used as the event time")
	}
}

// A provider that writes no time of its own leaves the record's write time as
// the best answer available, and says so.
func TestRecordTimeIsUsedWhenThereIsNothingBetter(t *testing.T) {
	f, err := Flatten(load(t, "security_4662"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.TimeSource != "TimeCreated" {
		t.Errorf("time source: %q", f.TimeSource)
	}
	if f.Time.IsZero() {
		t.Error("no time at all was read")
	}
}

// An unparseable UtcTime must not throw away the time the record header
// already gave, and must not pass unnoticed either.
func TestUnreadableProviderTimeFallsBackAndIsRecorded(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider":    map[string]any{"Name": "Microsoft-Windows-Sysmon"},
				"EventID":     map[string]any{"Value": int64(1)},
				"TimeCreated": map[string]any{"SystemTime": 1599826222.0},
			},
			"EventData": map[string]any{"UtcTime": "yesterday"},
		},
	}
	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.TimeSource != "TimeCreated" || f.Time.IsZero() {
		t.Errorf("the header time was lost: %q %s", f.TimeSource, f.Time)
	}
	if len(f.Skipped) != 1 || f.Skipped[0] != "UtcTime" {
		t.Errorf("a time that could not be read went unrecorded: %v", f.Skipped)
	}
}

// The four ways this corpus writes "nothing here". They stay in Fields, because
// a rule must see what the provider wrote; what they must not do is become a
// value in anything a person reads.
func TestUnavailableRecognisesTheProvidersBlanks(t *testing.T) {
	for _, s := range []string{"", " ", "-", "?", "Binary Data"} {
		if !Unavailable(s) {
			t.Errorf("%q was taken for information", s)
		}
	}
	for _, s := range []string{"IEWIN7", "0", "false", "C:\\Windows", "Binary Data is fine"} {
		if Unavailable(s) {
			t.Errorf("%q was taken for a blank", s)
		}
	}
}

// The same record that has a "?" for Company keeps it in Fields: the flattener
// does not get to decide what detection sees.
func TestBlanksAreStillInTheFlatView(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider": map[string]any{"Name": "Microsoft-Windows-Sysmon"},
				"EventID":  map[string]any{"Value": int64(1)},
			},
			"EventData": map[string]any{"Company": "?", "RuleName": "-"},
		},
	}
	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Fields["Company"] != "?" || f.Fields["RuleName"] != "-" {
		t.Errorf("a value the provider wrote was filtered out of the flat view: %v", f.Fields)
	}
}

// Two events in this corpus say the audit log was cleared — Security 1102 and
// System 104 — and both write their fields in a UserData block instead of
// EventData. Reading only System and EventData left them with no actor, which
// on "somebody cleared the log" is the single thing worth knowing.
//
// The record below is built to the shape Windows documents rather than captured
// from the corpus, for the same reason as TestGoParserShape: the dump that the
// fixtures come from is produced by this package, and until this code read
// UserData it could not show what was in there. The run against the real files
// is what confirms it.
func TestUserDataIsRead(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider": map[string]any{"Name": "Microsoft-Windows-Eventlog"},
				"EventID":  int64(1102),
				"Channel":  "Security",
				"Computer": "DC1.insecurebank.local",
			},
			"UserData": map[string]any{
				"LogFileCleared": map[string]any{
					"SubjectUserName":   "bob",
					"SubjectDomainName": "insecurebank",
					"SubjectUserSid":    "S-1-5-21-738609754-2819869699-4189121830-1108",
					"SubjectLogonId":    "0x8d6e9",
				},
			},
		},
	}

	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if f.Fields["SubjectUserName"] != "bob" {
		t.Errorf("the account that cleared the log was lost: %v", f.Fields)
	}
	if f.Fields["SubjectUserSid"] == "" {
		t.Error("SubjectUserSid is empty")
	}
	// The block is named, so that one nobody expected shows up in the audit
	// instead of being dropped on the assumption that it is uninteresting.
	if len(f.Blocks) != 1 || f.Blocks[0] != "UserData/LogFileCleared" {
		t.Errorf("the block was not recorded: %v", f.Blocks)
	}
}

// A record with nothing but System and EventData reports no extra blocks, so
// that the audit line stays quiet on the 31,241 records that have none.
func TestOrdinaryRecordHasNoExtraBlocks(t *testing.T) {
	f, err := Flatten(load(t, "sysmon_process_creation"), normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Blocks) != 0 {
		t.Errorf("blocks reported on an ordinary record: %v", f.Blocks)
	}
}

// HexInt stands in for the named types a parser is free to return. The EVTX
// library declares `type HexInt uint64` and hands it back for fields such as
// Keywords.
type HexInt uint64

// A type switch on uint64 does not match a named type whose underlying type is
// uint64. Getting this wrong made every record in the pinned corpus unreadable,
// with nothing in the output to say why, so it gets a test of its own.
func TestNamedIntegerTypesAreNotRejected(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider":      map[string]any{"Name": "Microsoft-Windows-Sysmon"},
				"EventID":       map[string]any{"Value": HexInt(1)},
				"Keywords":      HexInt(0x8000000000000000),
				"EventRecordID": HexInt(42),
				"Computer":      "MSEDGEWIN10",
			},
			"EventData": map[string]any{
				"GrantedAccess": HexInt(4112),
			},
		},
	}
	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatalf("a named integer type made the whole record unreadable: %v", err)
	}
	if f.EventID != 1 {
		t.Errorf("EventID: %d", f.EventID)
	}
	if f.Fields["Keywords"] != "9223372036854775808" {
		t.Errorf("Keywords: %q", f.Fields["Keywords"])
	}
	if f.Fields["GrantedAccess"] != "0x1010" {
		t.Errorf("GrantedAccess through a named type: %q", f.Fields["GrantedAccess"])
	}
}

// The event id has to be known before the data is rendered, because how a
// field is written can depend on it. Values from the 5158 of
// LSASS_campaign_01, in the shape the EVTX parser hands back, with ProcessId
// as the integer that parser produces.
func TestTheEventIdIsKnownBeforeTheDataIsRendered(t *testing.T) {
	rec := map[string]any{"Event": map[string]any{
		"System": map[string]any{
			"Provider": map[string]any{"#attributes": map[string]any{"Name": "Microsoft-Windows-Security-Auditing"}},
			"EventID":  json.Number("5158"),
			"Channel":  "Security",
		},
		"EventData": map[string]any{"ProcessId": int64(1048), "SourcePort": "63829"},
	}}
	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Fields["ProcessId"]; got != "1048" {
		t.Errorf("ProcessId of a 5158 rendered as %q; Windows writes 1048", got)
	}
}
