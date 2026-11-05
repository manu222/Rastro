package auditd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manu222/rastro/internal/event"
)

// Every line in these tests was taken out of the pinned Linux corpus, not
// written by hand. The format has three styles in eight files and the
// differences are exactly the kind of thing an author imagining a format does
// not imagine.

func parse(t *testing.T, line string) Record {
	t.Helper()
	rec, err := Parse(line)
	if err != nil {
		t.Fatalf("did not parse: %v\n%s", err, line)
	}
	return rec
}

// The raw style: seconds since the epoch, no space before the colon, values
// bare.
func TestTheRawStyle(t *testing.T) {
	rec := parse(t, `type=EXECVE msg=audit(1723044684.257:15795): argc=3 a0="sudo" a1="LD_PRELOAD=./myfopen.so" a2="./prog"`)

	if rec.Type != "EXECVE" {
		t.Errorf("type: %q", rec.Type)
	}
	if rec.Serial != "15795" {
		t.Errorf("serial: %q", rec.Serial)
	}
	if rec.Time.Format("2006-01-02 15:04:05.000") != "2024-08-07 15:31:24.257" {
		t.Errorf("time: %s", rec.Time)
	}
	if rec.Fields["a1"] != "LD_PRELOAD=./myfopen.so" {
		t.Errorf("a1: %q", rec.Fields["a1"])
	}
}

// The style a log has after `ausearch -i`: a human date with a space in it,
// a space before the colon, and values with no quotes. The timestamp is the
// awkward part, because it contains both a space and colons and the serial is
// after the last of them.
func TestTheRenderedStyle(t *testing.T) {
	rec := parse(t, `type=EXECVE msg=audit(02/20/2025 13:06:23.771:103922) : argc=3 a0=sudo a1=LD_PRELOAD=./myfopen.so a2=./prog `)

	if rec.Serial != "103922" {
		t.Errorf("serial: %q", rec.Serial)
	}
	if rec.Time.Format("2006-01-02 15:04:05.000") != "2025-02-20 13:06:23.771" {
		t.Errorf("time: %s", rec.Time)
	}
	if rec.Fields["a1"] != "LD_PRELOAD=./myfopen.so" {
		t.Errorf("a1: %q", rec.Fields["a1"])
	}
	if rec.Fields["argc"] != "3" {
		t.Errorf("argc: %q", rec.Fields["argc"])
	}
}

// A message inside a message. This is where a SERVICE_STOP keeps the unit it
// stopped, which is the field the rule needs, and the nested message's closing
// quote is followed immediately by two more fields with no space between them.
func TestAMessageNestedInsideAMessage(t *testing.T) {
	rec := parse(t, `type=SERVICE_STOP msg=audit(1722965459.146:15207): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=auditd comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'UID="root" AUID="unset"`)

	if rec.Fields["unit"] != "auditd" {
		t.Errorf("the unit the rule needs was not lifted out of the nested message: %q", rec.Fields["unit"])
	}
	if rec.Fields["exe"] != "/usr/lib/systemd/systemd" {
		t.Errorf("exe: %q", rec.Fields["exe"])
	}
	if rec.Fields["res"] != "success" {
		t.Errorf("res: %q", rec.Fields["res"])
	}
	// The fields that follow the nested message with no space before them.
	if rec.Fields["UID"] != "root" {
		t.Errorf("a field after the closing quote was lost: %q", rec.Fields["UID"])
	}
	if rec.Fields["AUID"] != "unset" {
		t.Errorf("AUID: %q", rec.Fields["AUID"])
	}
}

// The documented blind spot, and it is in the corpus three times: a space after
// the equals sign means there is no unit field at all, and the rule that looks
// for a stopped service cannot see those records.
//
// This test asserts the gap rather than papering over it. Reading ahead to the
// next word would be inventing a value the log does not have, and it would make
// this reader disagree with every other tool: Zircolite misses the same three
// records, and the manifests record its count.
func TestASpaceAfterTheEqualsSignLeavesNoField(t *testing.T) {
	rec := parse(t, `type=SERVICE_STOP msg=audit(1722964315.586:9899): pid=1 uid=0 msg='unit= auditd comm="systemd" res=success'UID="root"`)

	if v, present := rec.Fields["unit"]; present && v != "" {
		t.Errorf("a value was invented for a field the log does not carry: %q", v)
	}
	// And the rest of the nested message still parses, so one malformed field
	// does not cost the record.
	if rec.Fields["comm"] != "systemd" {
		t.Errorf("the fields after the malformed one were lost: %q", rec.Fields["comm"])
	}
	if rec.Fields["res"] != "success" {
		t.Errorf("res: %q", rec.Fields["res"])
	}
}

// A nested field can collide with an outer one. A SERVICE_STOP has a pid of its
// own and its nested message does not, but the general case has to keep both.
func TestACollisionKeepsTheOuterValue(t *testing.T) {
	rec := parse(t, `type=TEST msg=audit(1.0:1): pid=1 msg='pid=99 res=success'`)

	if rec.Fields["pid"] != "1" {
		t.Errorf("the nested value displaced the outer one: %q", rec.Fields["pid"])
	}
	if rec.Shadowed["pid"] != "99" {
		t.Errorf("the displaced value was dropped: %v", rec.Shadowed)
	}
}

// auditd writes unsigned -1 for a login uid that does not exist, and
// `ausearch -i` writes the word unset for the same thing. Printing 4294967295
// as an account would be printing a number that identifies nobody.
func TestTheWaysAnAuditLogSaysNothing(t *testing.T) {
	for _, v := range []string{"", "?", "(null)", "unset", "4294967295", "-1"} {
		if !Unavailable(v) {
			t.Errorf("%q was taken for information", v)
		}
	}
	for _, v := range []string{"0", "1000", "root", "auditd", "/bin/sh"} {
		if Unavailable(v) {
			t.Errorf("%q was taken for a blank", v)
		}
	}

	rec := parse(t, `type=SERVICE_STOP msg=audit(1.0:1): uid=0 auid=4294967295 ses=4294967295`)
	e := rec.Event("f.log", 1)
	// auid is unset, so the process uid is the best answer available — and it
	// is labelled, because a bare 0 in the account column of a report reads
	// like a name and is not one.
	if e.User.Value != "root (uid 0)" {
		t.Errorf("auid is unset so uid is the best answer: %q", e.User.Value)
	}
	for _, ent := range e.Entities {
		if ent.Kind == event.KindSession {
			t.Errorf("a session of 4294967295 was recorded: %+v", ent)
		}
	}
}

// A number is not a name. uid 0 is root on every POSIX system by definition,
// which makes it the one identifier that can be translated without a copy of
// the machine's own password file; every other number is labelled and left
// alone, because resolving it needs an /etc/passwd this tool does not have.
func TestNumericAccountsAreLabelledAndOnlyZeroIsNamed(t *testing.T) {
	for in, want := range map[string]string{
		"0":      "root (uid 0)",
		"1000":   "uid 1000",
		"ubuntu": "ubuntu",
		"root":   "root",
	} {
		if got := account(in); got != want {
			t.Errorf("%q: want %q, got %q", in, want, got)
		}
	}
}

// `ausearch -i` resolves a system call and writes its name beside the number.
// "system call rename" is something a person reads; "system call 82" is
// something they have to look up.
func TestAResolvedSyscallNameIsPreferredOverItsNumber(t *testing.T) {
	e := parse(t, `type=SYSCALL msg=audit(1.0:1): syscall=82 SYSCALL=rename exe="/usr/bin/crontab"`).Event("f.log", 1)
	if e.Action != "system call rename" {
		t.Errorf("action: %q", e.Action)
	}
	// And with only the number, the number stays a number rather than being
	// translated from a table that is per architecture.
	e = parse(t, `type=SYSCALL msg=audit(1.0:1): syscall=82`).Event("f.log", 1)
	if e.Action != "system call 82" {
		t.Errorf("action: %q", e.Action)
	}
}

// The login uid survives sudo and the process uid does not, so a report that
// wants to know who is behind something wants auid.
func TestTheLoginAccountIsPreferredOverTheProcessAccount(t *testing.T) {
	rec := parse(t, `type=SYSCALL msg=audit(1.0:1): uid=0 auid=1000 AUID="ubuntu" UID="root"`)
	e := rec.Event("f.log", 1)
	if e.User.Value != "ubuntu" {
		t.Errorf("want the resolved login account, got %q", e.User.Value)
	}
}

// auditd writes one field per argument and no whole command line. The rules
// match the arguments one by one, so the fields stay as they are and the joined
// form is added beside them.
func TestTheArgumentsAreJoinedWithoutReplacingThem(t *testing.T) {
	rec := parse(t, `type=EXECVE msg=audit(1.0:1): argc=3 a0="sudo" a1="LD_PRELOAD=./x.so" a2="./prog"`)
	e := rec.Event("f.log", 1)

	if e.Process.CommandLine.Value != "sudo LD_PRELOAD=./x.so ./prog" {
		t.Errorf("command line: %q", e.Process.CommandLine.Value)
	}
	if e.Raw["a1"] != "LD_PRELOAD=./x.so" {
		t.Error("the individual arguments the rules match on were replaced")
	}
}

// A gap in the numbering is recorded rather than closed over, because a command
// line with a piece missing reads as a different command.
func TestAMissingArgumentIsMarkedAndNotClosedOver(t *testing.T) {
	rec := parse(t, `type=EXECVE msg=audit(1.0:1): argc=3 a0="sh" a2="-c"`)
	e := rec.Event("f.log", 1)
	if !strings.Contains(e.Process.CommandLine.Value, "<missing a1>") {
		t.Errorf("the gap was hidden: %q", e.Process.CommandLine.Value)
	}
}

// A line that is not an audit record is counted, not ignored. A file where
// nothing parses is a file in a format this reader does not understand, and
// that has to be distinguishable from an empty log.
func TestLinesThatAreNotRecordsAreCounted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.log")
	body := strings.Join([]string{
		`type=EXECVE msg=audit(1.0:1): argc=1 a0="sh"`,
		`Aug  6 11:04:12 host sshd[123]: Accepted password for ubuntu`,
		``,
		`type=PATH msg=audit(2.0:2): name="/etc/ld.so.preload" nametype=NORMAL`,
		`this is not a record at all`,
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	r := New(dir)
	var seen int
	stats, err := r.ReadFile(path, func(*event.Event) error { seen++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 2 || seen != 2 {
		t.Errorf("records: %d emitted %d", stats.Records, seen)
	}
	if stats.Unparsed != 2 {
		t.Errorf("unparsed: %d", stats.Unparsed)
	}
	if stats.FirstFailure == nil {
		t.Error("a count of unreadable lines came with no cause")
	}
}

// A record with no readable timestamp must not come out dated at the epoch,
// because 1970 in a timeline is a lie that sorts first.
func TestARecordWithNoReadableTimeSaysSo(t *testing.T) {
	rec, err := Parse(`type=EXECVE msg=audit(not-a-time:7): argc=1 a0="sh"`)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.NoTime {
		t.Error("an unreadable timestamp was not reported")
	}
	if !rec.Time.IsZero() {
		t.Errorf("a time was invented: %s", rec.Time)
	}
	if rec.Serial != "7" {
		t.Errorf("the serial was lost with the time: %q", rec.Serial)
	}
}

// The classes the rules and the report depend on.
func TestRecordTypesAreClassified(t *testing.T) {
	cases := map[string]struct {
		line   string
		class  event.Class
		action string
	}{
		"execve":  {`type=EXECVE msg=audit(1.0:1): argc=1 a0="sh"`, event.ClassProcess, "command executed"},
		"path":    {`type=PATH msg=audit(1.0:1): name="/etc/ld.so.preload" nametype=NORMAL`, event.ClassFile, "file touched"},
		"service": {`type=SERVICE_STOP msg=audit(1.0:1): msg='unit=auditd res=success'`, event.ClassService, "service stopped"},
		"audit":   {`type=CONFIG_CHANGE msg=audit(1.0:1): op=remove_rule`, event.ClassLog, "audit configuration changed"},
		"sudo":    {`type=USER_CMD msg=audit(1.0:1): cmd=6C73`, event.ClassAuth, "command run through sudo"},
	}
	for name, c := range cases {
		e := parse(t, c.line).Event("f.log", 1)
		if e.Class != c.class {
			t.Errorf("%s: class %s", name, e.Class)
		}
		if e.Action != c.action {
			t.Errorf("%s: action %q", name, e.Action)
		}
	}

	// An unknown type keeps its fields and claims nothing about what it was.
	e := parse(t, `type=SOMETHING_NEW msg=audit(1.0:1): key=value`).Event("f.log", 1)
	if e.Class != event.ClassUnknown || e.Action != "" {
		t.Errorf("an unknown record type was given a meaning: %s %q", e.Class, e.Action)
	}
	if e.Raw["key"] != "value" {
		t.Error("an unknown record type lost its fields")
	}
}

// The file name is not a hostname, however tempting. auditd writes a node name
// only when it was configured to, and the samples were not.
func TestTheFileNameIsNotAHostname(t *testing.T) {
	e := parse(t, `type=EXECVE msg=audit(1.0:1): argc=1 a0="sh"`).Event("web01.log", 1)
	if e.Host.Known() {
		t.Errorf("a host was invented: %q", e.Host.Value)
	}

	e = parse(t, `type=EXECVE msg=audit(1.0:1): node=web01 argc=1 a0="sh"`).Event("f.log", 1)
	if e.Host.Value != "web01" {
		t.Errorf("a node name the log does carry was not used: %q", e.Host.Value)
	}
}
