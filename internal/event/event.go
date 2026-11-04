// Package event defines the shape every piece of evidence is turned into
// before anything else looks at it.
//
// Three decisions are baked into these types, and each of them is expensive to
// change later.
//
// The first is that an event carries its native fields as well as its
// normalised ones. Detection runs against the native fields, because that is
// what Sigma rules are written against — this repository's own rules and the
// thousands published by SigmaHQ alike. Normalisation exists for grouping,
// correlation and the report, not for matching. The report also has to be able
// to show the original event behind any claim it makes, so the native fields
// have to survive anyway; translating the rules away from them would buy
// nothing.
//
// The second is that an event is transient. It is built, passed through the
// pipeline and dropped. A gigabyte of evidence is on the order of a million
// events, and holding those in memory is how an analysis tool kills the laptop
// it is being run on. What survives is the finding and a reference back to the
// record it came from.
//
// The third is provenance. Some evidence does not state who did something: an
// auditd PATH record names a file and nothing else. The tool can often work it
// out from a neighbouring record, and it should — leaving the field empty blinds
// the analyst. But a value the tool deduced and a value it read are different
// kinds of fact, and presenting them the same way is how a correlation engine
// ends up asserting things that are not true. Every field here says which it is.
package event

import "time"

// Provenance records where a value came from. The zero value is Unknown, which
// is deliberate: a field nobody filled in must never read as observed fact.
type Provenance uint8

const (
	// Unknown means the evidence did not say and nothing could be deduced.
	Unknown Provenance = iota
	// Observed means the value was read from the record itself.
	Observed
	// Inferred means the tool deduced it. Why must explain how.
	Inferred
)

func (p Provenance) String() string {
	switch p {
	case Observed:
		return "observed"
	case Inferred:
		return "inferred"
	default:
		return "unknown"
	}
}

// Field is a value plus the answer to "how do you know that".
type Field struct {
	Value string
	From  Provenance
	// Why explains an inferred value in a sentence an analyst can check, for
	// example "process 1266 on this host, started 14:02:11, runs as ubuntu".
	// It is empty for observed values, where the record is the explanation.
	Why string
}

// Seen returns a field read straight from the evidence.
func Seen(value string) Field {
	if value == "" {
		return Field{}
	}
	return Field{Value: value, From: Observed}
}

// Deduced returns a field the tool worked out, with its reasoning attached.
// A deduction without a reason is refused: it would be indistinguishable from
// a guess by the time it reached the report.
func Deduced(value, why string) Field {
	if value == "" || why == "" {
		return Field{}
	}
	return Field{Value: value, From: Inferred, Why: why}
}

// Known reports whether there is a value at all.
func (f Field) Known() bool { return f.From != Unknown && f.Value != "" }

// Trusted reports whether the value was read rather than deduced. Grouping may
// use either, but an incident built out of deductions is worth less than one
// built out of observations, and the confidence score has to be able to tell.
func (f Field) Trusted() bool { return f.From == Observed }

// Class is what kind of activity the event describes, independent of which
// product recorded it. A process starting is the same class whether it came
// from a Sysmon event or an auditd syscall, and that is the whole point of
// normalising.
//
// The names follow OCSF, whose class identifiers were read from the schema
// rather than remembered: File System Activity is 1001, Scheduled Job Activity
// 1006, Process Activity 1007, Event Log Activity 1008, Account Change 3001,
// Group Management 3006, Network Activity 4001. The numbers are not encoded
// here on purpose. Registry and named pipe activity live in OCSF's Windows
// extension, whose identifiers are built differently, and emitting a number
// that is almost right is worse than emitting none. The mapping belongs with
// the serialiser, where it can be checked against the schema at the time.
type Class uint8

const (
	ClassUnknown      Class = iota
	ClassProcess            // a process started, ended, or was opened by another
	ClassFile               // a file was created, written, deleted or renamed
	ClassRegistry           // a registry key or value was created, set or deleted
	ClassNetwork            // a connection, a resolution, a transfer
	ClassAuth               // a logon, a failure, a privilege use
	ClassAccount            // an account or a group was created or changed
	ClassScheduledJob       // a scheduled task, a cron entry, a systemd timer
	ClassService            // a service or daemon started, stopped or was installed
	ClassPipe               // a named pipe was created or connected to
	ClassLog                // the logging subsystem itself was touched
)

func (c Class) String() string {
	switch c {
	case ClassProcess:
		return "process"
	case ClassFile:
		return "file"
	case ClassRegistry:
		return "registry"
	case ClassNetwork:
		return "network"
	case ClassAuth:
		return "auth"
	case ClassAccount:
		return "account"
	case ClassScheduledJob:
		return "scheduled_job"
	case ClassService:
		return "service"
	case ClassPipe:
		return "pipe"
	case ClassLog:
		return "log"
	default:
		return "unknown"
	}
}

// Kind is the sort of thing an entity is. Grouping happens over entities: the
// report is organised by which machines, accounts and groups were involved,
// and only then by what happened to each of them.
type Kind uint8

const (
	KindUnknown Kind = iota
	KindHost
	KindAccount
	KindGroup
	KindFile
	KindRegistry
	KindPipe
	KindAddress // an IP address, or a host:port once the network source lands
	KindDomain
	KindHash
)

func (k Kind) String() string {
	switch k {
	case KindHost:
		return "host"
	case KindAccount:
		return "account"
	case KindGroup:
		return "group"
	case KindFile:
		return "file"
	case KindRegistry:
		return "registry"
	case KindPipe:
		return "pipe"
	case KindAddress:
		return "address"
	case KindDomain:
		return "domain"
	case KindHash:
		return "hash"
	default:
		return "unknown"
	}
}

// Entity is something an event touched, with the provenance of the value.
type Entity struct {
	Kind  Kind
	Field Field
	// Role says how the entity took part, in the source's own words — "target",
	// "source", "added_to". It is free text because the vocabulary differs per
	// source and inventing a closed list now would mean rewriting it per source
	// later.
	Role string
}

// Process is kept apart from the other entities for two reasons. It has
// several attributes rather than one value, and it is the only entity with a
// relationship that matters on its own: a parent and a child process are two
// steps of the same action, and the correlation engine walks that link.
type Process struct {
	Image       Field // full path to the executable
	CommandLine Field
	PID         Field
	// GUID is a process identifier that is unique over time. Sysmon emits one
	// precisely because process identifiers get recycled, and inheriting a user
	// by PID alone can attribute an action to whoever held that number before.
	// auditd has no equivalent, so on Linux the same inference has to be bounded
	// by time and is worth less confidence.
	GUID Field
}

// Empty reports whether anything is known about the process at all.
func (p Process) Empty() bool {
	return !p.Image.Known() && !p.CommandLine.Known() && !p.PID.Known() && !p.GUID.Known()
}

// Origin points back at the record this event was built from. It is what makes
// it possible to throw the event away and still show it later: the report keeps
// the finding and this reference, and the raw fields are re-read or embedded
// for the handful of events that produced findings.
type Origin struct {
	// Path is the evidence file, relative to the directory the analysis was
	// given, so that a report does not leak the directory layout of whoever ran
	// it.
	Path string
	// Record identifies the entry inside that file: the EVTX record number, the
	// line number of a text log, the frame number of a capture.
	Record int64
	// Producer is what wrote the evidence — "Microsoft-Windows-Sysmon/Operational",
	// "auditd" — which is also what tells the detection stage which native field
	// names to expect.
	Producer string
}

// Fields holds the event exactly as the source recorded it, with the source's
// own field names. Detection reads from here, and so does level three of the
// report.
//
// This is the hot path: one of these per event, a million events in a large
// case. It is a map for now because correctness comes first and the shape of
// the lookups is not settled yet; the allocation cost gets measured before the
// pipeline is called finished, not guessed at now.
type Fields map[string]string

// Event is one normalised record. Construction is cheap on purpose: the
// pipeline builds one, passes it along and lets it go.
type Event struct {
	// Time is when the thing happened, not when it was recorded or read.
	// Aligning clocks across sources is the hard part of phase three; until
	// then this is whatever the source said, in UTC.
	Time     time.Time
	Class    Class
	Activity string // the source's own word: "CreateKey", "SetValue", "execve"

	Origin Origin

	Host    Field
	User    Field
	Process Process
	Parent  Process

	Entities []Entity

	Raw Fields
}

// Add appends an entity, ignoring the ones with nothing in them so that callers
// can map fields blindly without checking each one first.
func (e *Event) Add(kind Kind, role string, f Field) {
	if !f.Known() {
		return
	}
	e.Entities = append(e.Entities, Entity{Kind: kind, Field: f, Role: role})
}

// First returns the first entity of a kind. The second result reports whether
// there was one, so that a caller can tell "absent" from "present but empty".
func (e *Event) First(kind Kind) (Entity, bool) {
	for _, en := range e.Entities {
		if en.Kind == kind {
			return en, true
		}
	}
	return Entity{}, false
}

// FullyObserved reports whether every value this event carries was read rather
// than deduced. An incident grouped out of events that are all fully observed
// can be stated plainly; one that rests on deductions has to say so.
func (e *Event) FullyObserved() bool {
	for _, f := range []Field{
		e.Host, e.User,
		e.Process.Image, e.Process.CommandLine, e.Process.PID, e.Process.GUID,
		e.Parent.Image, e.Parent.CommandLine, e.Parent.PID, e.Parent.GUID,
	} {
		if f.From == Inferred {
			return false
		}
	}
	for _, en := range e.Entities {
		if en.Field.From == Inferred {
			return false
		}
	}
	return true
}
