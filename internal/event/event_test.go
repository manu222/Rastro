package event

import "testing"

// The point of these is not coverage for its own sake. Each one pins down a
// decision that was argued about, so that changing it later is a conscious act
// rather than an accident.

func TestUnsetFieldIsNotFact(t *testing.T) {
	var f Field
	if f.Known() {
		t.Error("a field nobody filled in reads as known")
	}
	if f.Trusted() {
		t.Error("a field nobody filled in reads as observed; the zero value must be Unknown")
	}
}

func TestDeductionRequiresAReason(t *testing.T) {
	if got := Deduced("ubuntu", ""); got.Known() {
		t.Errorf("a deduction with no reasoning was accepted: %+v", got)
	}
	got := Deduced("ubuntu", "process 1266 on this host runs as ubuntu")
	if !got.Known() {
		t.Fatal("a deduction with reasoning was rejected")
	}
	if got.Trusted() {
		t.Error("a deduction reads as observed, which is the failure this type exists to prevent")
	}
}

func TestEmptyValueIsNeverStored(t *testing.T) {
	if Seen("").Known() {
		t.Error("an empty observed value reads as known")
	}
	var e Event
	e.Add(KindAccount, "target", Seen(""))
	if len(e.Entities) != 0 {
		t.Errorf("an empty entity was recorded: %+v", e.Entities)
	}
}

func TestFullyObservedTurnsOffOnOneDeduction(t *testing.T) {
	e := Event{
		Host: Seen("MSEDGEWIN10"),
		User: Seen("insecurebank\\Administrator"),
	}
	e.Add(KindFile, "target", Seen(`C:\Windows\Temp\x.exe`))
	if !e.FullyObserved() {
		t.Fatal("an event built only from observations does not report as fully observed")
	}

	e.Add(KindAccount, "owner", Deduced("ubuntu", "from the syscall record with the same audit id"))
	if e.FullyObserved() {
		t.Error("one deduced entity did not lower the event from fully observed")
	}
}

func TestFirstDistinguishesAbsentFromEmpty(t *testing.T) {
	var e Event
	if _, ok := e.First(KindHost); ok {
		t.Error("an entity was reported on an event that has none")
	}
	e.Add(KindHost, "", Seen("DC1"))
	en, ok := e.First(KindHost)
	if !ok || en.Field.Value != "DC1" {
		t.Errorf("entity not found after being added: %+v %v", en, ok)
	}
}
