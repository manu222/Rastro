// Package auditd reads Linux audit logs.
//
// There is no library here and no parser dependency, because an audit log is
// text and the work is in the details of that text rather than in its
// structure. The details are not the ones the documentation suggests. Over the
// pinned Linux corpus, eight files written by three different setups, this is
// what actually arrives:
//
//	type=EXECVE msg=audit(02/20/2025 13:06:23.771:103922) : argc=3 a0=sudo a1=LD_PRELOAD=./myfopen.so
//	type=EXECVE msg=audit(1723044684.257:15795): argc=3 a0="sudo" a1="LD_PRELOAD=./myfopen.so"
//	type=SERVICE_STOP msg=audit(1722965459.146:15207): pid=1 msg='unit=auditd comm="systemd" res=success'UID="root"
//
// Three timestamp and quoting styles in one corpus: a human-readable date from
// a log passed through `ausearch -i`, the raw epoch form, values quoted in one
// file and bare in another, a space before the colon in one setup and none in
// the next, a message nested inside a message, and that nested message's
// closing quote followed immediately by more fields with no space between them.
// Every one of those is handled because a record it cannot read is a record
// that silently does not exist.
//
// What counts as an event is a decision worth stating. Properly, an audit event
// is every record sharing one serial — the SYSCALL, its EXECVE, its CWD and its
// PATH records are one execution seen four ways. This reader emits one event
// per record and keeps the serial on each, for two reasons. The rules are
// written against single records: the LD_PRELOAD rule matches an EXECVE whose
// a1 begins with LD_PRELOAD=, or a PATH naming /etc/ld.so.preload, and neither
// needs the others. And joining them is a correlation question, which belongs
// with the rest of the correlation rather than inside a parser. The serial is
// recorded so that the joining can happen later without re-reading anything.
package auditd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/event"
)

// Limits bound what one file is allowed to cost. An audit log is attacker-
// influenced input like any other evidence.
type Limits struct {
	// MaxRecords stops after this many records in one file. Zero means no
	// limit, which is only reasonable in tests.
	MaxRecords int
	// MaxBytes refuses a file larger than this before opening it.
	MaxBytes int64
	// MaxLine is the longest line that will be read. An audit record with a
	// long command line is ordinary; a megabyte on one line is not a record.
	MaxLine int
}

// DefaultLimits are generous for real evidence and small enough that a
// malformed file cannot exhaust the machine.
func DefaultLimits() Limits {
	return Limits{MaxRecords: 20_000_000, MaxBytes: 8 << 30, MaxLine: 1 << 20}
}

// Stats is what the reader can say about a file afterwards.
type Stats struct {
	Records int
	// Unparsed counts lines that are not audit records at all. They are
	// counted rather than ignored: a file where most lines do not parse is a
	// file in a format this reader does not understand, and the difference
	// between that and an empty log has to be visible.
	Unparsed int
	// FirstFailure is the first line that could not be read, so that a count
	// comes with a cause.
	FirstFailure error
	// Stopped reports that a limit cut the read short.
	Stopped string
}

// Reader walks one evidence directory's worth of audit logs.
type Reader struct {
	Limits Limits
	// Root is the directory the analysis was given. Paths recorded on events
	// are relative to it.
	Root string
}

// New returns a reader with the default limits.
func New(root string) *Reader {
	return &Reader{Limits: DefaultLimits(), Root: root}
}

// ReadFile walks one file, calling emit once per record.
func (r *Reader) ReadFile(path string, emit func(*event.Event) error) (Stats, error) {
	var stats Stats

	info, err := os.Stat(path)
	if err != nil {
		return stats, err
	}
	if r.Limits.MaxBytes > 0 && info.Size() > r.Limits.MaxBytes {
		return stats, fmt.Errorf("%s is %d bytes, over the %d byte limit",
			filepath.Base(path), info.Size(), r.Limits.MaxBytes)
	}

	fd, err := os.Open(path)
	if err != nil {
		return stats, err
	}
	defer fd.Close()

	rel := path
	if r.Root != "" {
		if p, err := filepath.Rel(r.Root, path); err == nil {
			rel = filepath.ToSlash(p)
		}
	}

	scan := bufio.NewScanner(fd)
	max := r.Limits.MaxLine
	if max <= 0 {
		max = 1 << 20
	}
	scan.Buffer(make([]byte, 0, 64<<10), max)

	line := int64(0)
	for scan.Scan() {
		line++
		text := strings.TrimSpace(scan.Text())
		if text == "" {
			continue
		}
		if r.Limits.MaxRecords > 0 && stats.Records >= r.Limits.MaxRecords {
			stats.Stopped = fmt.Sprintf("record limit of %d reached", r.Limits.MaxRecords)
			return stats, nil
		}

		rec, err := Parse(text)
		if err != nil {
			stats.Unparsed++
			if stats.FirstFailure == nil {
				stats.FirstFailure = fmt.Errorf("line %d: %w", line, err)
			}
			continue
		}
		stats.Records++
		if err := emit(rec.Event(rel, line)); err != nil {
			return stats, err
		}
	}
	if err := scan.Err(); err != nil {
		return stats, fmt.Errorf("%s: %w", rel, err)
	}
	return stats, nil
}

// Record is one parsed audit record.
type Record struct {
	Type   string
	Time   time.Time
	Serial string
	// Fields holds every key the record carries, including the ones that were
	// nested inside a message.
	Fields map[string]string
	// Shadowed holds a value a nested field displaced. A SERVICE_STOP has a
	// pid of its own and its nested message has another; dropping one silently
	// would be dropping evidence.
	Shadowed map[string]string
	// NoTime reports that the record carries no readable timestamp, so that an
	// event at the zero time is never mistaken for one at the epoch.
	NoTime bool
}

// Parse reads one line.
func Parse(line string) (Record, error) {
	rec := Record{Fields: map[string]string{}}

	// type=X comes first in every record of this corpus, and the format
	// guarantees it.
	rest := line
	if !strings.HasPrefix(rest, "type=") {
		return rec, fmt.Errorf("does not begin with type=")
	}
	space := strings.IndexByte(rest, ' ')
	if space < 0 {
		return rec, fmt.Errorf("has a type and nothing else")
	}
	rec.Type = rest[len("type="):space]
	rec.Fields["type"] = rec.Type
	rest = rest[space+1:]

	// msg=audit(TIMESTAMP:SERIAL). The timestamp itself contains colons and
	// may contain a space, so the serial is taken from the last colon inside
	// the parentheses rather than from the first.
	const header = "msg=audit("
	start := strings.Index(rest, header)
	if start < 0 {
		return rec, fmt.Errorf("has no audit header")
	}
	end := strings.IndexByte(rest[start:], ')')
	if end < 0 {
		return rec, fmt.Errorf("has an unclosed audit header")
	}
	inside := rest[start+len(header) : start+end]
	rest = rest[start+end+1:]

	colon := strings.LastIndexByte(inside, ':')
	if colon < 0 {
		return rec, fmt.Errorf("audit header %q carries no serial", inside)
	}
	rec.Serial = inside[colon+1:]
	rec.Fields["audit_serial"] = rec.Serial
	stamp := inside[:colon]
	rec.Fields["audit_time"] = stamp
	if t, err := parseStamp(stamp); err == nil {
		rec.Time = t
	} else {
		rec.NoTime = true
	}

	// The fields. A space before the colon appears in one setup and not in the
	// next, so both are skipped.
	rest = strings.TrimLeft(rest, " ")
	rest = strings.TrimPrefix(rest, ":")
	parseFields(rest, &rec)

	return rec, nil
}

// parseStamp reads the two timestamp styles in this corpus.
//
// The raw form is seconds since the epoch with milliseconds. The other comes
// from a log that has been through `ausearch -i`, which rewrites it as a local
// date — and that is a real loss: the zone it was local to is not in the line.
// It is read as UTC and said so here, because a timestamp quietly shifted by
// the reader's own zone is worse than one that is honestly off by a known
// amount.
func parseStamp(s string) (time.Time, error) {
	// The epoch form is read as two integers and not as a float, for the same
	// reason the normaliser refuses an imprecise one: 1723044684.257 through a
	// float64 comes back as ...684.256999969, and a timestamp that is a
	// millisecond early is a timestamp that can reorder two events.
	if whole, frac, ok := splitSeconds(s); ok {
		secs, err := strconv.ParseInt(whole, 10, 64)
		if err == nil {
			nanos, err := fractionToNanos(frac)
			if err == nil {
				return time.Unix(secs, nanos).UTC(), nil
			}
		}
	}
	for _, layout := range []string{
		"01/02/2006 15:04:05.999",
		"01/02/2006 15:04:05",
		"2006-01-02 15:04:05.999",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("timestamp %q is neither a number of seconds nor a date this reader knows", s)
}

// splitSeconds takes an epoch timestamp apart without arithmetic.
func splitSeconds(s string) (whole, frac string, ok bool) {
	whole, frac = s, ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		whole, frac = s[:dot], s[dot+1:]
	}
	if whole == "" {
		return "", "", false
	}
	for i := 0; i < len(whole); i++ {
		if (whole[i] < '0' || whole[i] > '9') && !(i == 0 && whole[i] == '-') {
			return "", "", false
		}
	}
	for i := 0; i < len(frac); i++ {
		if frac[i] < '0' || frac[i] > '9' {
			return "", "", false
		}
	}
	return whole, frac, true
}

// fractionToNanos reads the digits after the point as a fraction of a second,
// padded rather than multiplied so that nothing is rounded.
func fractionToNanos(frac string) (int64, error) {
	if frac == "" {
		return 0, nil
	}
	if len(frac) > 9 {
		frac = frac[:9]
	}
	for len(frac) < 9 {
		frac += "0"
	}
	return strconv.ParseInt(frac, 10, 64)
}

// parseFields walks a run of key=value pairs.
//
// Values come bare, in double quotes, or in single quotes, and a single-quoted
// value is itself a run of key=value pairs: that is where a SERVICE_STOP keeps
// the unit it stopped, which is the field the rule needs. The nested pairs are
// lifted into the same map, because a rule says `unit: auditd` and knows
// nothing about the nesting.
func parseFields(s string, rec *Record) {
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return
		}
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return
		}
		// A key never contains a space. When one appears to, the pair before it
		// was malformed — `unit= auditd` with a space after the equals sign is
		// in this corpus three times — and the token is skipped rather than
		// taken as the end of the line. Giving up here cost the comm, exe and
		// res fields of every such record, which is more evidence than the one
		// field the log really is missing.
		key := s[:eq]
		if strings.ContainsAny(key, " \t") {
			skip := strings.IndexAny(s, " \t")
			if skip < 0 {
				return
			}
			s = s[skip+1:]
			continue
		}
		s = s[eq+1:]

		switch {
		case strings.HasPrefix(s, `"`):
			value, remainder := upTo(s[1:], '"')
			rec.set(key, value)
			s = remainder

		case strings.HasPrefix(s, `'`):
			value, remainder := upTo(s[1:], '\'')
			// The nested message. Its own text is kept as well as its parts,
			// because a rule may match the whole thing.
			rec.set(key, value)
			parseFields(value, rec)
			s = remainder

		default:
			end := strings.IndexAny(s, " \t")
			if end < 0 {
				rec.set(key, s)
				return
			}
			rec.set(key, s[:end])
			s = s[end:]
		}
	}
}

// upTo returns the text before the next delimiter and whatever follows it.
// A closing quote with no space after it is ordinary in this corpus — res=success'UID="root" —
// so the remainder is returned as it stands and not trimmed.
func upTo(s string, delim byte) (value, rest string) {
	if i := strings.IndexByte(s, delim); i >= 0 {
		return s[:i], s[i+1:]
	}
	// An unclosed quote: the rest of the line is the value. Better than
	// discarding it.
	return s, ""
}

// set records a field, keeping whatever a nested field displaced.
func (rec *Record) set(key, value string) {
	if key == "" {
		return
	}
	if old, clash := rec.Fields[key]; clash {
		if old == value {
			return
		}
		// The outer value wins and the nested one is recorded as displaced.
		// Which way round that goes matters: the outer field is the record's
		// own, and a nested message describes whatever the record is about.
		if rec.Shadowed == nil {
			rec.Shadowed = map[string]string{}
		}
		rec.Shadowed[key] = value
		return
	}
	rec.Fields[key] = value
}

// Unavailable reports whether a value is one of the ways an audit log writes
// "there is nothing here".
//
// The interesting one is 4294967295. That is unsigned -1, and auditd writes it
// for a login uid that does not exist: a process started by the system rather
// than by a person. `ausearch -i` renders the same thing as the word unset. A
// report that printed 4294967295 as an account would be printing a number that
// identifies nobody, which is the Linux version of a machine called "-".
func Unavailable(s string) bool {
	switch strings.TrimSpace(s) {
	case "", "?", "(null)", "unset", "4294967295", "-1":
		return true
	}
	return false
}

// Event turns a record into an event.
func (rec Record) Event(path string, line int64) *event.Event {
	e := &event.Event{
		Time:     rec.Time,
		Activity: rec.Type,
		Origin: event.Origin{
			Path:      path,
			Record:    line,
			Producer:  "auditd",
			TimeField: "audit_time",
			Product:   "linux",
			Service:   "auditd",
		},
		Raw: event.Fields(rec.Fields),
	}

	// A host, when the log carries one. auditd only writes a node name if it
	// was configured to, and the samples in this corpus were not, so this is
	// usually empty — and leaving it empty is the answer. The file name is not
	// a hostname, however tempting.
	for _, key := range []string{"node", "hostname"} {
		if v := rec.Fields[key]; !Unavailable(v) {
			e.Host = event.Seen(v)
			e.Add(event.KindHost, "", e.Host)
			break
		}
	}

	// The account. auid is the login uid, which survives sudo and su, and is
	// therefore the one worth reporting: uid says what the process was running
	// as, auid says who logged in. `ausearch -i` adds AUID and UID with the
	// names resolved, and a name is more use than a number.
	switch {
	case !Unavailable(rec.Fields["AUID"]):
		e.User = event.Seen(account(rec.Fields["AUID"]))
	case !Unavailable(rec.Fields["auid"]):
		e.User = event.Seen(account(rec.Fields["auid"]))
	case !Unavailable(rec.Fields["UID"]):
		e.User = event.Seen(account(rec.Fields["UID"]))
	case !Unavailable(rec.Fields["uid"]):
		e.User = event.Seen(account(rec.Fields["uid"]))
	}
	if e.User.Known() {
		e.Add(event.KindAccount, "actor", e.User)
	}

	e.Process = event.Process{
		Image: fieldOf(rec, "exe"),
		PID:   fieldOf(rec, "pid"),
	}
	if !e.Process.Image.Known() {
		// comm is the process name without its path, which is less than exe
		// and more than nothing.
		e.Process.Image = fieldOf(rec, "comm")
	}
	e.Parent = event.Process{PID: fieldOf(rec, "ppid")}

	if ses := rec.Fields["ses"]; !Unavailable(ses) {
		// The audit session, which is the Linux equivalent of a logon id and
		// the key the correlation stage will join on.
		e.Add(event.KindSession, "actor", event.Seen(ses))
	}

	classify(rec, e)
	return e
}

// account renders an account the way a report should show it.
//
// A bare 0 in the account column of a report reads like a name and is not one.
// Numeric identifiers are labelled as such so that nobody mistakes one for a
// user called "0", and zero is named: uid 0 is root on every POSIX system by
// definition, which makes it the one number that can be translated without a
// copy of the machine's own password file. Every other number stays a number,
// because resolving it needs /etc/passwd from the machine the log came from and
// this tool does not have it.
func account(v string) string {
	if _, err := strconv.Atoi(v); err != nil {
		return v
	}
	if v == "0" {
		return "root (uid 0)"
	}
	return "uid " + v
}

func fieldOf(rec Record, key string) event.Field {
	if v := rec.Fields[key]; !Unavailable(v) {
		return event.Seen(v)
	}
	return event.Field{}
}

// classify says what a record type means.
//
// The table covers the types this corpus contains and the ones the rules are
// written against. A type that is not here keeps its fields and gets no class,
// which is the honest answer: the record was read and nothing is claimed about
// what it was.
func classify(rec Record, e *event.Event) {
	switch rec.Type {
	case "EXECVE":
		e.Class = event.ClassProcess
		e.Action = "command executed"
		// auditd writes one field per argument and no whole command line.
		// Joining them on the separator a shell would have used is not a
		// deduction: every piece was recorded.
		if cmd := commandLine(rec); cmd != "" {
			e.Process.CommandLine = event.Seen(cmd)
		}

	case "SYSCALL":
		e.Class = event.ClassProcess
		e.Action = "system call"
		// `ausearch -i` resolves the call and writes its name in an upper-case
		// field beside the raw number, exactly as it does for accounts. The
		// name is preferred because "system call rename" is something a person
		// reads and "system call 82" is something they have to look up — and
		// the number is never translated here, because the table that would do
		// it is per architecture and inventing one would be the same mistake
		// as inventing a message-table label.
		switch {
		case rec.Fields["SYSCALL"] != "":
			e.Action = "system call " + rec.Fields["SYSCALL"]
		case rec.Fields["syscall"] != "":
			e.Action = "system call " + rec.Fields["syscall"]
		}
		e.Add(event.KindFile, "image", fieldOf(rec, "exe"))

	case "PATH":
		e.Class = event.ClassFile
		e.Action = "file touched"
		if t := rec.Fields["nametype"]; t != "" {
			e.Activity = t
		}
		e.Add(event.KindFile, "object", fieldOf(rec, "name"))

	case "SERVICE_STOP":
		e.Class = event.ClassService
		e.Action = "service stopped"
		e.Add(event.KindService, "subject", fieldOf(rec, "unit"))

	case "SERVICE_START":
		e.Class = event.ClassService
		e.Action = "service started"
		e.Add(event.KindService, "subject", fieldOf(rec, "unit"))

	case "USER_CMD":
		e.Class = event.ClassAuth
		e.Action = "command run through sudo"

	case "USER_AUTH", "USER_ACCT", "CRED_ACQ", "CRED_REFR", "CRED_DISP":
		e.Class = event.ClassAuth
		e.Action = "credential check"

	case "USER_LOGIN", "USER_START", "LOGIN":
		e.Class = event.ClassAuth
		e.Action = "logon"

	case "USER_END", "USER_LOGOUT":
		e.Class = event.ClassAuth
		e.Action = "session ended"

	case "ADD_USER", "ADD_GROUP", "USER_MGMT", "ROLE_ASSIGN", "ACCT_LOCK":
		e.Class = event.ClassAccount
		e.Action = "account or group changed"

	case "CONFIG_CHANGE", "DAEMON_START", "DAEMON_END", "DAEMON_ABORT":
		// The audit subsystem itself. An attacker turning auditing off is the
		// Linux equivalent of clearing the Windows event log.
		e.Class = event.ClassLog
		e.Action = "audit configuration changed"

	case "CWD", "PROCTITLE", "SOCKADDR":
		// Context for the record that shares its serial rather than an event
		// of its own.
		e.Class = event.ClassUnknown
	}
}

// commandLine joins the argument fields of an EXECVE.
//
// argc says how many there are, and they are numbered a0 upwards. The count is
// trusted over the field names so that a gap in the numbering cannot silently
// truncate a command, and the fields are read by name so that a wrong argc
// cannot invent one.
func commandLine(rec Record) string {
	count := 0
	if n, err := strconv.Atoi(rec.Fields["argc"]); err == nil && n > 0 && n < 4096 {
		count = n
	}
	var parts []string
	for i := 0; ; i++ {
		v, ok := rec.Fields["a"+strconv.Itoa(i)]
		if !ok {
			if i >= count {
				break
			}
			// A missing argument in the middle: recorded as a gap rather than
			// closed over, because a command line with a piece removed reads
			// as a different command.
			parts = append(parts, "<missing a"+strconv.Itoa(i)+">")
			continue
		}
		parts = append(parts, v)
		if i > 4096 {
			break
		}
	}
	return strings.Join(parts, " ")
}
