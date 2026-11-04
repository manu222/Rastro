package winevent

import (
	"testing"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/normalise"
)

func classify(t *testing.T, rec map[string]any) *event.Event {
	t.Helper()
	f, err := Flatten(rec, normalise.Default())
	if err != nil {
		t.Fatal(err)
	}
	e := &event.Event{Time: f.Time, Activity: f.Fields["EventID"], Raw: event.Fields(f.Fields)}
	Classify(f, e)
	return e
}

func entity(e *event.Event, kind event.Kind, role string) (event.Entity, bool) {
	for _, ent := range e.Entities {
		if ent.Kind == kind && ent.Role == role {
			return ent, true
		}
	}
	return event.Entity{}, false
}

// A process creation out of the corpus, end to end: the actor, its parent, the
// account and the image are what the report is built from.
func TestProcessCreationIsClassified(t *testing.T) {
	e := classify(t, load(t, "sysmon_process_creation"))

	if e.Class != event.ClassProcess {
		t.Errorf("class: %s", e.Class)
	}
	if e.Action != "process created" {
		t.Errorf("action: %q", e.Action)
	}
	if e.Process.Image.Value == "" || e.Process.CommandLine.Value == "" {
		t.Errorf("the acting process is empty: %+v", e.Process)
	}
	if e.Parent.Image.Value == "" {
		t.Errorf("the parent is empty: %+v", e.Parent)
	}
	if e.Process.GUID.Value == "" {
		t.Error("ProcessGuid did not reach the event; without it a recycled pid cannot be told apart")
	}
	// Sysmon 1 is the one event that names the user, and the only one that
	// carries the logon session the others lack.
	if e.User.Value == "" {
		t.Error("the account is empty on the one Sysmon event that writes it")
	}
	if !e.User.Trusted() {
		t.Errorf("the account was recorded as something other than observed: %+v", e.User)
	}
	if _, ok := entity(e, event.KindSession, "actor"); !ok {
		t.Errorf("the logon session was not recorded: %+v", e.Entities)
	}
	if _, ok := entity(e, event.KindFile, "image"); !ok {
		t.Errorf("the image is not an entity: %+v", e.Entities)
	}
}

// The event rule 9 reads for DCSync. Its object is a directory GUID, so what
// the mapping can offer is the class and the account behind it — and that it
// does so is what makes the finding attributable.
func TestDirectoryAccessIsAttributed(t *testing.T) {
	e := classify(t, load(t, "security_4662"))

	if e.Class != event.ClassDirectory {
		t.Errorf("class: %s", e.Class)
	}
	// insecurebank\DC1$: the two halves of the name as Windows itself writes
	// them, joined the way Windows writes them.
	if e.User.Value != `insecurebank\DC1$` {
		t.Errorf("account: %q", e.User.Value)
	}
	if e.Activity != "Object Access" {
		t.Errorf("the provider's own word for what happened was lost: %q", e.Activity)
	}
}

// Sysmon 10 is the reason the event model has a target process. The actor here
// is unremarkable and the target is lsass.exe; a model with one process field
// would have to pick one, and either choice loses the finding.
func TestProcessAccessKeepsBothSides(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider": map[string]any{"Name": "Microsoft-Windows-Sysmon"},
				"EventID":  map[string]any{"Value": int64(10)},
				"Computer": "MSEDGEWIN10",
			},
			"EventData": map[string]any{
				"SourceImage":       `C:\Users\Public\a.exe`,
				"SourceProcessId":   int64(1532),
				"SourceProcessGUID": "365ABB72-4055-5CC8-0000-0010769D0B00",
				"TargetImage":       `C:\Windows\System32\lsass.exe`,
				"TargetProcessId":   int64(640),
				"TargetProcessGUID": "365ABB72-3FDE-5CC8-0000-0010142B0000",
				"GrantedAccess":     "0x1f1fff",
			},
		},
	}
	e := classify(t, rec)

	if e.Process.Image.Value != `C:\Users\Public\a.exe` {
		t.Errorf("actor: %q", e.Process.Image.Value)
	}
	if e.Target.Image.Value != `C:\Windows\System32\lsass.exe` {
		t.Errorf("target: %q", e.Target.Image.Value)
	}
	// GUID in capitals on event 10 and Guid on event 8. The table spells each
	// one the way its own event does, and this is the test that says so.
	if e.Target.GUID.Value == "" {
		t.Error("TargetProcessGUID was not read; event 8 spells the same field TargetProcessGuid")
	}
	// No account: this event names none, and inventing one from the process
	// would be exactly the inference the provenance model exists to prevent.
	if e.User.Known() {
		t.Errorf("an account appeared on an event that carries none: %+v", e.User)
	}
}

// The one place in the corpus where the Security convention breaks:
// TargetUserName is the group, and the account that went into it is MemberSid.
func TestGroupMembershipMapsTheGroupAsAGroup(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider": map[string]any{"Name": "Microsoft-Windows-Security-Auditing"},
				"EventID":  map[string]any{"Value": int64(4732)},
				"Computer": "MSEDGEWIN10",
			},
			"EventData": map[string]any{
				"SubjectUserName":   "IEUser",
				"SubjectDomainName": "MSEDGEWIN10",
				"SubjectUserSid":    "S-1-5-21-3461203602-4096304019-2269080069-1000",
				"SubjectLogonId":    "0x27a68f",
				"TargetUserName":    "Administrators",
				"TargetDomainName":  "Builtin",
				"TargetSid":         "S-1-5-32-544",
				"MemberName":        "-",
				"MemberSid":         "S-1-5-21-3461203602-4096304019-2269080069-501",
			},
		},
	}
	e := classify(t, rec)

	g, ok := entity(e, event.KindGroup, "group")
	if !ok || g.Field.Value != "Administrators" {
		t.Errorf("the group was not recorded as a group: %+v", e.Entities)
	}
	m, ok := entity(e, event.KindAccount, "member")
	if !ok || m.Field.Value == "" {
		t.Errorf("the account added to the group was lost: %+v", e.Entities)
	}
	// MemberName is "-" on this event, which is Windows saying it has nothing
	// to write there. One member entity, not two, and not one called "-".
	count := 0
	for _, ent := range e.Entities {
		if ent.Role == "member" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("want one member entity, got %d: %+v", count, e.Entities)
	}
}

// Service Control Manager writes no named fields at all. Without the table a
// report would show param1 and param2 and mean nothing to anyone.
func TestServiceStateReadsPositionalParameters(t *testing.T) {
	rec := map[string]any{
		"Event": map[string]any{
			"System": map[string]any{
				"Provider": map[string]any{"Name": "Service Control Manager"},
				"EventID":  map[string]any{"Value": int64(7036)},
				"Computer": "01566s-win16-ir.threebeesco.com",
			},
			"EventData": map[string]any{
				"param1": "Windows Error Reporting Service",
				"param2": "running",
			},
		},
	}
	e := classify(t, rec)

	if e.Class != event.ClassService {
		t.Errorf("class: %s", e.Class)
	}
	if e.Activity != "running" {
		t.Errorf("state: %q", e.Activity)
	}
	s, ok := entity(e, event.KindService, "subject")
	if !ok || s.Field.Value != "Windows Error Reporting Service" {
		t.Errorf("the service was not recorded: %+v", e.Entities)
	}
}

// An event nobody mapped is read, kept and left unclassified. Most of this
// corpus is RPC trace events that no table covers, and they still belong in a
// timeline with their raw fields.
func TestUnmappedEventIsKeptUnclassified(t *testing.T) {
	e := classify(t, load(t, "rpc_without_channel"))

	if e.Class != event.ClassUnknown {
		t.Errorf("an unmapped event was given a class: %s", e.Class)
	}
	if e.Action != "" {
		t.Errorf("an unmapped event was given an action: %q", e.Action)
	}
	if len(e.Raw) == 0 {
		t.Error("an unmapped event lost its fields")
	}
}

func TestLogonTypeIsTranslatedAndUnknownOnesAreNot(t *testing.T) {
	for in, want := range map[string]string{"2": "interactive", "3": "network", "5": "service", "10": "remote interactive"} {
		if got, ok := Explain("LogonType", in); !ok || got != want {
			t.Errorf("LogonType %s: want %q, got %q", in, want, got)
		}
	}
	// 0 is not in Microsoft's list, so it stays a 0 rather than being given a
	// name that is not written down anywhere.
	if got, ok := Explain("LogonType", "0"); ok || got != "0" {
		t.Errorf("LogonType 0 was translated into %q", got)
	}
	// A number under another field name is not a logon type.
	if got, _ := Explain("KeyLength", "5"); got != "5" {
		t.Errorf("a number was translated outside its own field: %q", got)
	}
}

func TestLogonFailureCodesAreReadable(t *testing.T) {
	if got, ok := Explain("SubStatus", "3221225578"); !ok || got != "wrong password" {
		t.Errorf("0xC000006A: %q", got)
	}
	if got, ok := Explain("Status", "3221225572"); !ok || got != "no such user" {
		t.Errorf("0xC0000064: %q", got)
	}
	// A code with no entry keeps its digits. An analyst can look that up; a
	// wrong label is not something they can catch.
	if got, ok := Explain("Status", "12345"); ok || got != "12345" {
		t.Errorf("an unknown status was given a name: %q", got)
	}
}

// The codes a real Windows installation resolved for us, and the reason each
// one is allowed to be in the table. If one of these ever changes, the test
// names the record it was read off so the claim can be checked again.
func TestResolvedCodesSayWhatWindowsSaysTheySay(t *testing.T) {
	for code, want := range map[string]string{
		"%%1842":  "yes",                               // KernelDebug on a 4826
		"%%1843":  "no",                                // four other fields of the same record
		"%%1794":  "never",                             // AccountExpires on a 4720
		"%%1792":  "changed, not shown",                // UserParameters, which is not nothing
		"%%1846":  "default",                           // ConfigAccessPolicy
		"%%1848":  "off",                               // the two launch types
		"%%14593": "outbound",                          // Direction on the only 5156
		"%%14611": "connect",                           // LayerName on the same record
		"%%14676": "Active Directory Domain Services",  // DSType on a 5136
		"%%2313":  "unknown user name or bad password", // FailureReason on the only 4625
	} {
		if got, ok := Explain("", code); !ok || got != want {
			t.Errorf("%s: want %q, got %q", code, want, got)
		}
	}
}

// %%1793 is absence and the other two are not. Getting this wrong would either
// put "value not set" in a report as if it were a display name, or hide the
// fact that an account never expires.
func TestOnlyTheValueNotSetCodeCountsAsAbsent(t *testing.T) {
	if !Unavailable("%%1793") {
		t.Error("%%1793 is Windows writing <value not set> and must not become a value")
	}
	for _, code := range []string{"%%1794", "%%1792", "%%1842"} {
		if Unavailable(code) {
			t.Errorf("%s says something and was treated as nothing", code)
		}
	}
}

func TestMessageReferencesAreRecognisedAndMostlyUntranslated(t *testing.T) {
	for _, v := range []string{"%%1842", "%%1833", "%%7688", "%%14675"} {
		if !IsMessageRef(v) {
			t.Errorf("%q was not recognised as a message reference", v)
		}
	}
	for _, v := range []string{"", "%", "%%", "%%abc", "1842", "-"} {
		if IsMessageRef(v) {
			t.Errorf("%q was taken for a message reference", v)
		}
	}
	if got, ok := Explain("ElevatedToken", "%%1842"); !ok || got != "yes" {
		t.Errorf("%%1842: %q", got)
	}
	// The honest half of the table: a code with no source stays as written.
	// These four are still outstanding and must not acquire a label until a
	// Windows installation has been made to say what they mean.
	// %%1936 and %%1937 stay here because Windows itself printed them raw: the
	// parameter strings were missing on the machine that rendered them, so
	// there is nothing to copy and nothing to check against.
	for _, code := range []string{"%%7688", "%%1936", "%%1937", "%%12544"} {
		if got, ok := Explain("Properties", code); ok || got != code {
			t.Errorf("an unresolved code was given a label: %s -> %q", code, got)
		}
	}
}
