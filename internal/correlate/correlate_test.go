package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/manu222/rastro/internal/event"
)

// The scenario these tests are built on is the one that motivated the package:
// something opens lsass as SYSTEM, and the only useful question is how it got
// there.
//
//	explorer.exe        IEWIN7\IEUser     Medium   session 0x9ff68
//	  cmd.exe           IEWIN7\IEUser     High
//	    psexesvc.exe    NT AUTHORITY\SYSTEM  System
//	      dump.exe      (names no account at all)
//	        opens lsass
//
// The event that fires the rule is the last line. It names no user, no parent
// and no session. Everything above it has to be recovered.

const (
	t0 = "2019-04-27T18:46:00Z"
	t1 = "2019-04-27T18:46:30Z"
	t2 = "2019-04-27T18:47:00Z"
	t3 = "2019-04-27T18:47:10Z"
	t4 = "2019-04-27T18:47:20Z"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// creation builds a Sysmon 1 the way the reader produces one.
func creation(t *testing.T, when, host, guid, pid, image, parentGUID, parentPID, parentImage, user, logonID, integrity string, record int64) *event.Event {
	t.Helper()
	e := &event.Event{
		Time:     at(t, when),
		Class:    event.ClassProcess,
		Action:   "process created",
		Activity: "1",
		Origin:   event.Origin{Path: "Credential Access/sample.evtx", Record: record, Producer: "Microsoft-Windows-Sysmon/Operational"},
		Host:     event.Seen(host),
		Process: event.Process{
			Image: event.Seen(image), PID: event.Seen(pid), GUID: event.Seen(guid),
		},
		Parent: event.Process{
			Image: event.Seen(parentImage), PID: event.Seen(parentPID), GUID: event.Seen(parentGUID),
		},
		Raw: event.Fields{
			"EventID": "1", "ProcessGuid": guid, "ProcessId": pid, "Image": image,
			"ParentProcessGuid": parentGUID, "ParentProcessId": parentPID,
			"LogonId": logonID, "IntegrityLevel": integrity, "User": user,
		},
	}
	if user != "" {
		e.User = event.Seen(user)
	}
	return e
}

// access builds the Sysmon 10 that fires the rule: it names its own process and
// nothing else.
func access(t *testing.T, when, host, guid, pid string, record int64) *event.Event {
	t.Helper()
	return &event.Event{
		Time:     at(t, when),
		Class:    event.ClassProcess,
		Action:   "process opened another process",
		Activity: "10",
		Origin:   event.Origin{Path: "Credential Access/lsass.evtx", Record: record},
		Host:     event.Seen(host),
		Process: event.Process{
			Image: event.Seen(`C:\Users\Public\dump.exe`), PID: event.Seen(pid), GUID: event.Seen(guid),
		},
		Target: event.Process{Image: event.Seen(`C:\Windows\System32\lsass.exe`)},
		Raw: event.Fields{
			"EventID": "10", "SourceProcessGUID": guid, "SourceProcessId": pid,
			"TargetImage": `C:\Windows\System32\lsass.exe`, "GrantedAccess": "0x1010",
		},
	}
}

func scenario(t *testing.T) (*Index, *event.Event) {
	t.Helper()
	ix := New()

	ix.Observe(creation(t, t0, "IEWIN7", "GUID-EXPLORER", "2836", `C:\Windows\explorer.exe`,
		"", "", "", `IEWIN7\IEUser`, "0x9ff68", "Medium", 10))
	ix.Observe(creation(t, t1, "IEWIN7", "GUID-CMD", "3680", `C:\Windows\System32\cmd.exe`,
		"GUID-EXPLORER", "2836", `C:\Windows\explorer.exe`, `IEWIN7\IEUser`, "0x9ff68", "High", 11))
	ix.Observe(creation(t, t2, "IEWIN7", "GUID-PSEXESVC", "1288", `C:\Windows\PSEXESVC.exe`,
		"GUID-CMD", "3680", `C:\Windows\System32\cmd.exe`, `NT AUTHORITY\SYSTEM`, "0x3e7", "System", 12))
	ix.Observe(creation(t, t3, "IEWIN7", "GUID-DUMP", "4940", `C:\Users\Public\dump.exe`,
		"GUID-PSEXESVC", "1288", `C:\Windows\PSEXESVC.exe`, `NT AUTHORITY\SYSTEM`, "0x3e7", "System", 13))

	// The logon that opened the session everything above ran in.
	ix.Observe(&event.Event{
		Time:   at(t, t0),
		Class:  event.ClassAuth,
		Action: "logon",
		Origin: event.Origin{Path: "Credential Access/logon.evtx", Record: 1},
		Host:   event.Seen("IEWIN7"),
		Raw: event.Fields{
			"EventID": "4624", "TargetLogonId": "0x9ff68",
			"TargetUserName": "IEUser", "TargetDomainName": "IEWIN7",
			"LogonType": "10", "IpAddress": "172.16.66.25", "WorkstationName": "ATTACKER",
		},
	})

	// The session SYSTEM processes run in. Having both in the evidence is what
	// makes the difference between the two questions visible.
	ix.Observe(&event.Event{
		Time:   at(t, t0),
		Class:  event.ClassAuth,
		Action: "logon",
		Origin: event.Origin{Path: "Credential Access/logon.evtx", Record: 2},
		Host:   event.Seen("IEWIN7"),
		Raw: event.Fields{
			"EventID": "4624", "TargetLogonId": "0x3e7",
			"TargetUserName": "SYSTEM", "TargetDomainName": "NT AUTHORITY",
			"LogonType": "5", "IpAddress": "-", "WorkstationName": "-",
		},
	})

	return ix, access(t, t4, "IEWIN7", "GUID-DUMP", "4940", 99)
}

// The question the package exists for: the event names nobody, and the answer
// has to come with the record it came from.
func TestTheAccountBehindAnEventThatNamesNone(t *testing.T) {
	ix, e := scenario(t)

	if e.User.Known() {
		t.Fatal("the test record is supposed to name no account")
	}
	got := ix.Account(e)
	if got.Value != `NT AUTHORITY\SYSTEM` {
		t.Errorf("account: %q", got.Value)
	}
	if got.Trusted() {
		t.Error("a deduced account was reported as observed, which is the one thing a report must not do")
	}
	if !strings.Contains(got.Why, "ProcessGuid") {
		t.Errorf("the deduction does not say how it was made: %q", got.Why)
	}
	if !strings.Contains(got.Why, "record 13") {
		t.Errorf("the deduction does not name the record it came from: %q", got.Why)
	}
}

// Opening lsass as SYSTEM is not the finding. How something became SYSTEM is.
func TestTheLineageShowsWhereTheAccountChanged(t *testing.T) {
	ix, e := scenario(t)

	steps, complete := ix.Ancestry(e)
	if len(steps) != 4 {
		t.Fatalf("want four steps up to explorer, got %d", len(steps))
	}
	if !complete {
		t.Error("the chain reaches a process with no parent recorded and should report itself complete")
	}
	want := []string{
		`C:\Users\Public\dump.exe`,
		`C:\Windows\PSEXESVC.exe`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\explorer.exe`,
	}
	for i, image := range want {
		if steps[i].Process.Image != image {
			t.Errorf("step %d: want %s, got %s", i, image, steps[i].Process.Image)
		}
	}

	esc := Escalations(steps)
	if len(esc) != 1 {
		t.Fatalf("want one account change, got %d: %+v", len(esc), esc)
	}
	if esc[0].FromUser != `IEWIN7\IEUser` || esc[0].ToUser != `NT AUTHORITY\SYSTEM` {
		t.Errorf("the change was read wrong: %+v", esc[0])
	}
	// And it has to point at the record where it happened, which is the one a
	// person will go and read.
	if esc[0].To.Origin.Record != 12 {
		t.Errorf("the change should be attributed to record 12: %+v", esc[0].To.Origin)
	}
	if esc[0].To.Image != `C:\Windows\PSEXESVC.exe` {
		t.Errorf("the process in between: %s", esc[0].To.Image)
	}
}

// From where. The session ties the whole lineage to a logon, and a type 10 with
// an address is a remote desktop from somewhere.
func TestTheSessionSaysWhereItWasRunning(t *testing.T) {
	ix, e := scenario(t)

	logon, who := ix.Session(e)
	if logon == nil {
		t.Fatal("the session was not resolved")
	}
	// Where it was running: the session the operating system gives its own
	// processes. True, and not the answer anybody is after.
	if logon.Type != "5" {
		t.Errorf("want the service session, got type %q", logon.Type)
	}
	if who.Trusted() {
		t.Error("a session reached through a chain is deduced, not observed")
	}
}

// And the question that matters: not where it was running, but where it came
// from. Four steps up the lineage there is a remote desktop logon from an
// address, and that is what a report has to name.
func TestTheEntryPointIsTheOldestSessionAnyoneLoggedInto(t *testing.T) {
	ix, e := scenario(t)

	steps, _ := ix.Ancestry(e)
	logon, who := ix.Entry(steps)
	if logon == nil {
		t.Fatal("the entry point was not resolved")
	}
	if logon.Type != "10" || logon.Address != "172.16.66.25" {
		t.Errorf("want the remote desktop logon, got %+v", logon)
	}
	if logon.Workstation != "ATTACKER" {
		t.Errorf("workstation: %q", logon.Workstation)
	}
	if who.Value != `IEWIN7\IEUser` {
		t.Errorf("the account behind the session: %q", who.Value)
	}
	if who.Trusted() {
		t.Error("an entry point reached through a lineage is deduced")
	}
	if !strings.Contains(who.Why, "explorer.exe") {
		t.Errorf("the deduction does not say which process the session belongs to: %q", who.Why)
	}
}

// Where the evidence stops, the answer stops. This is the case that separates
// an honest correlation from a confident one.
func TestAMissingCreationIsNotGuessedAt(t *testing.T) {
	ix := New()
	// Only the middle of the chain is in the evidence: the process that acted
	// was never recorded being created.
	ix.Observe(creation(t, t1, "IEWIN7", "GUID-CMD", "3680", `C:\Windows\System32\cmd.exe`,
		"GUID-EXPLORER", "2836", `C:\Windows\explorer.exe`, `IEWIN7\IEUser`, "0x9ff68", "High", 11))

	e := access(t, t4, "IEWIN7", "GUID-DUMP", "4940", 99)
	if _, _, ok := ix.Creator(e); ok {
		t.Error("a creation that is not in the evidence was found anyway")
	}
	if got := ix.Account(e); got.Known() {
		t.Errorf("an account was produced out of nothing: %+v", got)
	}
	steps, complete := ix.Ancestry(e)
	if len(steps) != 0 || complete {
		t.Errorf("a lineage was built without its first step: %+v", steps)
	}

	// And a chain that breaks in the middle reports itself incomplete rather
	// than claiming to have reached the root.
	mid := access(t, t4, "IEWIN7", "GUID-CMD", "3680", 98)
	steps, complete = ix.Ancestry(mid)
	if len(steps) != 1 {
		t.Fatalf("want the one step that is there, got %d", len(steps))
	}
	if complete {
		t.Error("the chain ends because the parent is missing, not because there is no parent")
	}
}

// A process identifier is unique over time and a process id is not. Where only
// the id is available the answer is offered once and withheld the moment it
// becomes a choice, because attributing an action to whoever held a recycled
// number earlier is how a report accuses the wrong person.
func TestAProcessIdIsOnlyFollowedWhenItIsUnambiguous(t *testing.T) {
	ix := New()
	// Two processes have held pid 4940 on this host, which is what recycling
	// looks like.
	ix.Observe(creation(t, t0, "IEWIN7", "", "4940", `C:\Windows\System32\notepad.exe`,
		"", "2836", "", `IEWIN7\IEUser`, "0x9ff68", "Medium", 20))
	ix.Observe(creation(t, t2, "IEWIN7", "", "4940", `C:\Users\Public\dump.exe`,
		"", "1288", "", `NT AUTHORITY\SYSTEM`, "0x3e7", "System", 21))

	// An event with no identifier of its own, after both.
	e := &event.Event{
		Time:    at(t, t4),
		Class:   event.ClassProcess,
		Host:    event.Seen("IEWIN7"),
		Process: event.Process{PID: event.Seen("4940")},
		Raw:     event.Fields{"EventID": "10", "ProcessId": "4940"},
	}
	if _, _, ok := ix.Creator(e); ok {
		t.Error("two candidates for the same pid produced an answer")
	}

	// With one candidate it is offered, and the reason says what it rests on.
	single := New()
	single.Observe(creation(t, t2, "IEWIN7", "", "4940", `C:\Users\Public\dump.exe`,
		"", "1288", "", `NT AUTHORITY\SYSTEM`, "0x3e7", "System", 21))
	p, why, ok := single.Creator(e)
	if !ok {
		t.Fatal("one candidate produced no answer")
	}
	if p.Image != `C:\Users\Public\dump.exe` {
		t.Errorf("wrong candidate: %s", p.Image)
	}
	if !strings.Contains(why, "the only process creation with pid") {
		t.Errorf("the reason does not admit what it rests on: %q", why)
	}
}

// A creation recorded after the event cannot be its creator, however well the
// identifiers line up.
func TestACreationAfterTheEventIsNotItsCreator(t *testing.T) {
	ix := New()
	ix.Observe(creation(t, t4, "IEWIN7", "", "4940", `C:\Users\Public\dump.exe`,
		"", "1288", "", `NT AUTHORITY\SYSTEM`, "0x3e7", "System", 21))

	e := &event.Event{
		Time:    at(t, t1),
		Class:   event.ClassProcess,
		Host:    event.Seen("IEWIN7"),
		Process: event.Process{PID: event.Seen("4940")},
		Raw:     event.Fields{"EventID": "10"},
	}
	if _, _, ok := ix.Creator(e); ok {
		t.Error("a process created later was offered as the creator")
	}
}

// The index holds what can be an ancestor and nothing else, which is what keeps
// it affordable on a real case.
func TestTheIndexIgnoresEverythingThatCannotBeAnAncestor(t *testing.T) {
	ix := New()
	for i := 0; i < 1000; i++ {
		ix.Observe(&event.Event{
			Class:  event.ClassNetwork,
			Action: "network connection",
			Raw:    event.Fields{"EventID": "3"},
		})
		ix.Observe(&event.Event{
			Class:  event.ClassRegistry,
			Action: "registry value set",
			Raw:    event.Fields{"EventID": "13"},
		})
	}
	processes, logons := ix.Size()
	if processes != 0 || logons != 0 {
		t.Errorf("the index kept %d processes and %d logons out of records that are neither", processes, logons)
	}

	ix.Observe(creation(t, t0, "IEWIN7", "GUID-ONE", "100", `C:\a.exe`, "", "", "", "u", "0x1", "High", 1))
	processes, _ = ix.Size()
	if processes != 1 {
		t.Errorf("want one process recorded, got %d", processes)
	}
}

// A cycle in damaged evidence must not spin.
func TestACycleStops(t *testing.T) {
	ix := New()
	ix.Observe(creation(t, t0, "H", "A", "1", "a.exe", "B", "2", "b.exe", "u", "0x1", "High", 1))
	ix.Observe(creation(t, t1, "H", "B", "2", "b.exe", "A", "1", "a.exe", "u", "0x1", "High", 2))

	e := &event.Event{
		Time:    at(t, t4),
		Class:   event.ClassProcess,
		Host:    event.Seen("H"),
		Process: event.Process{GUID: event.Seen("A")},
		Raw:     event.Fields{"EventID": "10"},
	}
	steps, complete := ix.Ancestry(e)
	if complete {
		t.Error("a cycle reported itself as a complete lineage")
	}
	if len(steps) > ix.Limits.MaxDepth {
		t.Errorf("the walk went past its limit: %d steps", len(steps))
	}
}

// Two accounts that differ only in case are the same account, and reporting a
// change between them would be noise in the one place a report has to be
// trusted.
func TestCaseIsNotAnAccountChange(t *testing.T) {
	ix := New()
	ix.Observe(creation(t, t0, "H", "A", "1", "a.exe", "", "", "", `IEWIN7\IEUser`, "0x1", "Medium", 1))
	ix.Observe(creation(t, t1, "H", "B", "2", "b.exe", "A", "1", "a.exe", `iewin7\ieuser`, "0x1", "High", 2))

	e := &event.Event{
		Time:    at(t, t4),
		Class:   event.ClassProcess,
		Host:    event.Seen("H"),
		Process: event.Process{GUID: event.Seen("B")},
		Raw:     event.Fields{"EventID": "10"},
	}
	steps, _ := ix.Ancestry(e)
	if esc := Escalations(steps); len(esc) != 0 {
		t.Errorf("a change of case was reported as a change of account: %+v", esc)
	}
}

// A host reuses logon ids, 0x3e7 on every boot and any id after a reboot. A
// repeat of the same session changes nothing; a different account under the
// same id is counted, and the first session is kept rather than replaced.
func TestAReusedLogonIdIsCountedRatherThanReplaced(t *testing.T) {
	logon := func(record int64, user, typ string) *event.Event {
		return &event.Event{
			Class: event.ClassAuth, Action: "logon",
			Origin: event.Origin{Path: "Security.evtx", Record: record},
			Host:   event.Seen("SCRANTON.dmevals.local"),
			Raw: event.Fields{"EventID": "4624", "TargetLogonId": "0x3c4a1",
				"TargetUserName": user, "TargetDomainName": "DMEVALS", "LogonType": typ},
		}
	}
	ix := New()
	ix.Observe(logon(1, "pbeesly", "2"))
	ix.Observe(logon(2, "pbeesly", "2"))
	if ix.LogonConflicts != 0 {
		t.Fatalf("a repeat of the same session was counted as a conflict")
	}
	ix.Observe(logon(3, "mscott", "3"))
	if ix.LogonConflicts != 1 || !strings.Contains(ix.FirstLogonConflict, "pbeesly") || !strings.Contains(ix.FirstLogonConflict, "mscott") {
		t.Errorf("conflicts %d, first %q", ix.LogonConflicts, ix.FirstLogonConflict)
	}
	if l := ix.logons["SCRANTON.dmevals.local\x000x3c4a1"]; l == nil || l.Origin.Record != 1 {
		t.Errorf("the first session was replaced: %+v", l)
	}
}
