package winevent

import (
	"strings"

	"github.com/manu222/rastro/internal/event"
)

// This file says what a Windows event means: which of its fields hold the
// process that acted, which hold the one it acted on, which account was behind
// it, and which values are the things a report is organised by.
//
// It is a table and not a function with a switch, because every entry in it was
// read off a real record. The dump the entries were written from is the one the
// reader itself produces over the pinned corpus — one record of each provider
// and event id, 53 of them — so a field name that is not in the evidence is not
// in here either. Three of the entries below are the direct result of looking:
//
//   - A Sysmon 10 writes SourceProcessGUID and a Sysmon 8 writes
//     SourceProcessGuid. Same provider, same concept, two spellings. Anything
//     cleverer than a literal name would have dropped one of them.
//   - A Sysmon 6 has no process at all. A driver load names the driver and
//     nothing about who loaded it, so the entry has no actor rather than an
//     actor built out of fields that are not there.
//   - On a Security 4732 the convention breaks: TargetUserName is the *group*
//     the member was added to, not a user. Every other Security event in the
//     corpus uses Target* for an account.
//
// What is deliberately not here: an event id nobody in the corpus produced.
// Guessing the field names of an event this project has never seen would put
// invented knowledge in the one place that decides what a report says happened.

// Proc names the fields that describe one process.
type Proc struct {
	Image       string
	CommandLine string
	PID         string
	GUID        string
}

// Account names the fields that describe one account. Windows splits a user
// across up to four fields and not every event writes all four.
type Account struct {
	Name   string
	Domain string
	SID    string
	// Logon is the logon session id. It is the only honest way to attach a user
	// to the events that name none: a process creation carries the session it
	// ran in, and so does the logon that started it.
	Logon string
}

// Ref turns one field into an entity of the report.
type Ref struct {
	Kind event.Kind
	// Field is the native field name, spelled exactly as the provider writes it.
	Field string
	// Role says what the thing was to this event — "target", "parent image" —
	// because a file path means something different depending on why it is
	// there.
	Role string
}

// Mapping is what one event id means.
type Mapping struct {
	Class  event.Class
	Action string
	// Activity names a field holding the provider's own word for what happened
	// ("SetValue", "Started", "running"), when it writes one. It is kept beside
	// Action rather than instead of it: one is evidence, the other is English.
	Activity string

	Actor  Proc
	Target Proc
	Parent Proc
	User   Account
	// Subject is a second account, the one the event was about rather than the
	// one that acted: the user created, the password reset, the member added.
	Subject  Account
	Entities []Ref
}

// The three providers whose records carry most of the meaning. Spelled as the
// provider writes its own name, which is what Flat.Producer holds.
const (
	sysmon   = "Microsoft-Windows-Sysmon"
	security = "Microsoft-Windows-Security-Auditing"
	eventlog = "Microsoft-Windows-Eventlog"
	scm      = "Service Control Manager"
	powersh  = "Microsoft-Windows-PowerShell"
)

// Shapes that repeat. Sysmon names the acting process the same way on most of
// its events, and Security names the acting account the same way on all of
// them, so the repetition is in the format and not in the knowledge.
var (
	sysmonActor = Proc{Image: "Image", CommandLine: "", PID: "ProcessId", GUID: "ProcessGuid"}

	// Subject* is the account that did the thing, on every Security event in
	// the corpus without exception.
	securitySubject = Account{
		Name:   "SubjectUserName",
		Domain: "SubjectDomainName",
		SID:    "SubjectUserSid",
		Logon:  "SubjectLogonId",
	}
	// Target* is the account it was done to. Two spellings of the SID field
	// are in use and which one appears is a property of the event id: 4624 and
	// 4688 write TargetUserSid, 4720 and 4732 write TargetSid.
	securityTargetUserSid = Account{Name: "TargetUserName", Domain: "TargetDomainName", SID: "TargetUserSid", Logon: "TargetLogonId"}
	securityTargetSid     = Account{Name: "TargetUserName", Domain: "TargetDomainName", SID: "TargetSid"}

	// Sysmon writes all three digests in one value, as SHA1=...,MD5=...,
	// SHA256=.... Kept whole: it still groups an event with every other
	// sighting of the same file, and splitting it into three entities is a
	// decision for when the report shows what pivoting by hash should do.
	hashOf  = Ref{Kind: event.KindHash, Field: "Hashes", Role: "image"}
	imageOf = Ref{Kind: event.KindFile, Field: "Image", Role: "image"}
)

// mappings is keyed by provider and event id.
var mappings = map[string]map[int]Mapping{
	sysmon: {
		1: {
			Class:  event.ClassProcess,
			Action: "process created",
			Actor:  Proc{Image: "Image", CommandLine: "CommandLine", PID: "ProcessId", GUID: "ProcessGuid"},
			Parent: Proc{Image: "ParentImage", CommandLine: "ParentCommandLine", PID: "ParentProcessId", GUID: "ParentProcessGuid"},
			// The one Sysmon event that names the user outright, and the one
			// that carries the logon session every other event lacks.
			User:     Account{Name: "User", Logon: "LogonId"},
			Entities: []Ref{imageOf, hashOf, {Kind: event.KindFile, Field: "ParentImage", Role: "parent image"}},
		},
		2: {
			Class:    event.ClassFile,
			Action:   "file creation time changed",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindFile, Field: "TargetFilename", Role: "target"}},
		},
		3: {
			Class:  event.ClassNetwork,
			Action: "network connection",
			Actor:  sysmonActor,
			User:   Account{Name: "User"},
			Entities: []Ref{
				imageOf,
				{Kind: event.KindAddress, Field: "DestinationIp", Role: "destination"},
				{Kind: event.KindAddress, Field: "SourceIp", Role: "source"},
				{Kind: event.KindHost, Field: "DestinationHostname", Role: "destination"},
			},
		},
		4: {
			// Sysmon starting or stopping is not a service event in a report:
			// it is the moment the evidence begins or ends. An analyst reading
			// a timeline needs to know where the recording has a hole.
			Class:    event.ClassLog,
			Action:   "Sysmon service state changed",
			Activity: "State",
		},
		5: {
			Class:    event.ClassProcess,
			Action:   "process ended",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf},
		},
		6: {
			// No actor: a driver load names the driver and says nothing about
			// who loaded it. The fields simply are not in the record.
			Class:    event.ClassModule,
			Action:   "driver loaded",
			Entities: []Ref{{Kind: event.KindFile, Field: "ImageLoaded", Role: "driver"}, hashOf},
		},
		7: {
			Class:    event.ClassModule,
			Action:   "module loaded",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindFile, Field: "ImageLoaded", Role: "module"}, hashOf},
		},
		8: {
			Class:  event.ClassProcess,
			Action: "thread created in another process",
			Actor:  Proc{Image: "SourceImage", PID: "SourceProcessId", GUID: "SourceProcessGuid"},
			Target: Proc{Image: "TargetImage", PID: "TargetProcessId", GUID: "TargetProcessGuid"},
			Entities: []Ref{
				{Kind: event.KindFile, Field: "SourceImage", Role: "image"},
				{Kind: event.KindFile, Field: "TargetImage", Role: "target image"},
				{Kind: event.KindFile, Field: "StartModule", Role: "start module"},
			},
		},
		10: {
			Class:  event.ClassProcess,
			Action: "process opened another process",
			// GUID in capitals here and Guid on event 8. Both are in the
			// corpus; neither is a typo in this file.
			Actor:  Proc{Image: "SourceImage", PID: "SourceProcessId", GUID: "SourceProcessGUID"},
			Target: Proc{Image: "TargetImage", PID: "TargetProcessId", GUID: "TargetProcessGUID"},
			Entities: []Ref{
				{Kind: event.KindFile, Field: "SourceImage", Role: "image"},
				{Kind: event.KindFile, Field: "TargetImage", Role: "target image"},
			},
		},
		11: {
			Class:    event.ClassFile,
			Action:   "file created",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindFile, Field: "TargetFilename", Role: "created"}},
		},
		12: {
			Class:    event.ClassRegistry,
			Action:   "registry key created or deleted",
			Activity: "EventType",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindRegistry, Field: "TargetObject", Role: "key"}},
		},
		13: {
			Class:    event.ClassRegistry,
			Action:   "registry value set",
			Activity: "EventType",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindRegistry, Field: "TargetObject", Role: "value"}},
		},
		16: {
			Class:  event.ClassLog,
			Action: "Sysmon configuration changed",
		},
		17: {
			Class:    event.ClassPipe,
			Action:   "named pipe created",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindPipe, Field: "PipeName", Role: "created"}},
		},
		18: {
			Class:    event.ClassPipe,
			Action:   "named pipe connected",
			Actor:    sysmonActor,
			Entities: []Ref{imageOf, {Kind: event.KindPipe, Field: "PipeName", Role: "connected"}},
		},
		// The three WMI events get a class, an actor and a verb, and no
		// entities. Their subjects are WMI filter and consumer names, which are
		// not any of the kinds a report groups by, and inventing a kind for
		// three events would be a worse answer than leaving the names in the
		// raw fields where the detail still shows.
		19: {
			Class:    event.ClassWMI,
			Action:   "WMI event filter registered",
			Activity: "Operation",
			User:     Account{Name: "User"},
		},
		20: {
			Class:    event.ClassWMI,
			Action:   "WMI event consumer registered",
			Activity: "Operation",
			User:     Account{Name: "User"},
		},
		21: {
			Class:    event.ClassWMI,
			Action:   "WMI consumer bound to filter",
			Activity: "Operation",
			User:     Account{Name: "User"},
		},
	},

	security: {
		4624: {
			Class:   event.ClassAuth,
			Action:  "logon",
			User:    securitySubject,
			Subject: securityTargetUserSid,
			Actor:   Proc{Image: "ProcessName", PID: "ProcessId"},
			Entities: []Ref{
				{Kind: event.KindAddress, Field: "IpAddress", Role: "source"},
				{Kind: event.KindHost, Field: "WorkstationName", Role: "source"},
				{Kind: event.KindSession, Field: "TargetLogonId", Role: "established"},
			},
		},
		4625: {
			Class:   event.ClassAuth,
			Action:  "logon failed",
			User:    securitySubject,
			Subject: securityTargetUserSid,
			Actor:   Proc{Image: "ProcessName", PID: "ProcessId"},
			Entities: []Ref{
				{Kind: event.KindAddress, Field: "IpAddress", Role: "source"},
				{Kind: event.KindHost, Field: "WorkstationName", Role: "source"},
			},
		},
		4627: {
			Class:   event.ClassAuth,
			Action:  "group membership of a logon",
			User:    securitySubject,
			Subject: securityTargetUserSid,
			// GroupMembership holds every group SID of the session in one
			// field, newline separated. Splitting it into entities needs a rule
			// about that field's format, which is a decision for when the
			// report exists and not a guess now.
		},
		// 4656 and 4663 describe access to an object whose kind is in a field
		// rather than in the event id: ObjectType is File, Key or Process
		// depending on the record. The class here is the common case and the
		// object's own type stays visible in Activity, because a class that is
		// sometimes wrong is worse than a coarse one.
		4656: {
			Class:    event.ClassFile,
			Action:   "handle to an object requested",
			Activity: "ObjectType",
			User:     securitySubject,
			Actor:    Proc{Image: "ProcessName", PID: "ProcessId"},
			Entities: []Ref{{Kind: event.KindFile, Field: "ObjectName", Role: "object"}},
		},
		4663: {
			Class:    event.ClassFile,
			Action:   "object accessed",
			Activity: "ObjectType",
			User:     securitySubject,
			Actor:    Proc{Image: "ProcessName", PID: "ProcessId"},
			Entities: []Ref{{Kind: event.KindFile, Field: "ObjectName", Role: "object"}},
		},
		4662: {
			// The event rule 9 reads for DCSync. ObjectName and ObjectType are
			// directory GUIDs rather than names, so they are left in the raw
			// fields: a GUID is not a thing a report can group by, and
			// resolving one needs the schema of the domain it came from.
			Class:    event.ClassDirectory,
			Action:   "directory object accessed",
			Activity: "OperationType",
			User:     securitySubject,
		},
		4672: {
			Class:  event.ClassAuth,
			Action: "special privileges assigned",
			User:   securitySubject,
			Entities: []Ref{
				{Kind: event.KindSession, Field: "SubjectLogonId", Role: "assigned to"},
			},
		},
		4688: {
			Class:  event.ClassProcess,
			Action: "process created",
			User:   securitySubject,
			Actor:  Proc{Image: "NewProcessName", CommandLine: "CommandLine", PID: "NewProcessId"},
			// The creator's pid is written as plain ProcessId while the created
			// one is NewProcessId, so the parent is assembled out of two fields
			// that do not share a prefix.
			Parent: Proc{Image: "ParentProcessName", PID: "ProcessId"},
			Entities: []Ref{
				{Kind: event.KindFile, Field: "NewProcessName", Role: "image"},
				{Kind: event.KindFile, Field: "ParentProcessName", Role: "parent image"},
			},
		},
		4698: {
			Class:    event.ClassScheduledJob,
			Action:   "scheduled task created",
			User:     securitySubject,
			Entities: []Ref{{Kind: event.KindTask, Field: "TaskName", Role: "created"}},
		},
		4699: {
			Class:    event.ClassScheduledJob,
			Action:   "scheduled task deleted",
			User:     securitySubject,
			Entities: []Ref{{Kind: event.KindTask, Field: "TaskName", Role: "deleted"}},
		},
		4702: {
			Class:    event.ClassScheduledJob,
			Action:   "scheduled task updated",
			User:     securitySubject,
			Entities: []Ref{{Kind: event.KindTask, Field: "TaskName", Role: "updated"}},
		},
		4703: {
			Class:   event.ClassAuth,
			Action:  "token privileges adjusted",
			User:    securitySubject,
			Subject: securityTargetUserSid,
			Actor:   Proc{Image: "ProcessName", PID: "ProcessId"},
			Entities: []Ref{
				{Kind: event.KindFile, Field: "ProcessName", Role: "image"},
			},
		},
		4719: {
			Class:  event.ClassLog,
			Action: "audit policy changed",
			User:   securitySubject,
		},
		4720: {
			Class:   event.ClassAccount,
			Action:  "user account created",
			User:    securitySubject,
			Subject: securityTargetSid,
		},
		4724: {
			Class:   event.ClassAccount,
			Action:  "password reset attempted",
			User:    securitySubject,
			Subject: securityTargetSid,
		},
		4732: {
			// Here Target* is not an account. TargetUserName is the group and
			// MemberSid is the account that went into it, which is the one
			// place in the corpus where the Security convention does not hold.
			Class:  event.ClassAccount,
			Action: "member added to a local group",
			User:   securitySubject,
			Entities: []Ref{
				{Kind: event.KindGroup, Field: "TargetUserName", Role: "group"},
				{Kind: event.KindAccount, Field: "MemberSid", Role: "member"},
				{Kind: event.KindAccount, Field: "MemberName", Role: "member"},
			},
		},
		4738: {
			Class:   event.ClassAccount,
			Action:  "user account changed",
			User:    securitySubject,
			Subject: securityTargetSid,
		},
		4742: {
			Class:   event.ClassAccount,
			Action:  "computer account changed",
			User:    securitySubject,
			Subject: securityTargetSid,
		},
		4768: {
			Class:   event.ClassAuth,
			Action:  "Kerberos ticket requested",
			Subject: securityTargetSid,
			Entities: []Ref{
				{Kind: event.KindAddress, Field: "IpAddress", Role: "source"},
				{Kind: event.KindService, Field: "ServiceName", Role: "requested"},
			},
		},
		4771: {
			Class:   event.ClassAuth,
			Action:  "Kerberos pre-authentication failed",
			Subject: securityTargetSid,
			Entities: []Ref{
				{Kind: event.KindAddress, Field: "IpAddress", Role: "source"},
				{Kind: event.KindService, Field: "ServiceName", Role: "requested"},
			},
		},
		4776: {
			Class:   event.ClassAuth,
			Action:  "credentials validated",
			Subject: Account{Name: "TargetUserName"},
			Entities: []Ref{
				{Kind: event.KindHost, Field: "Workstation", Role: "source"},
			},
		},
		4794: {
			Class:  event.ClassAccount,
			Action: "directory services restore mode password set",
			User:   securitySubject,
			Entities: []Ref{
				{Kind: event.KindHost, Field: "Workstation", Role: "source"},
			},
		},
		5136: {
			// ObjectDN is a distinguished name, which is neither an account nor
			// a group until something resolves it against the domain. It stays
			// in the raw fields for now.
			Class:    event.ClassDirectory,
			Action:   "directory object modified",
			Activity: "OperationType",
			User:     securitySubject,
		},
		5145: {
			Class:  event.ClassFile,
			Action: "network share object checked",
			User:   securitySubject,
			Entities: []Ref{
				{Kind: event.KindAddress, Field: "IpAddress", Role: "source"},
				{Kind: event.KindFile, Field: "RelativeTargetName", Role: "object"},
			},
		},
		5156: {
			// No account: the filtering platform records the connection and the
			// remote identity fields are the null SID. Leaving User empty is
			// the honest answer; filling it from the process would be a guess.
			Class:  event.ClassNetwork,
			Action: "connection allowed",
			Actor:  Proc{Image: "Application", PID: "ProcessID"},
			Entities: []Ref{
				{Kind: event.KindFile, Field: "Application", Role: "image"},
				{Kind: event.KindAddress, Field: "DestAddress", Role: "destination"},
				{Kind: event.KindAddress, Field: "SourceAddress", Role: "source"},
			},
		},
	},

	eventlog: {
		// The two events that say somebody cleared the log. Both keep their
		// fields in a UserData block, which is why reading only System and
		// EventData left them with no account on them at all.
		104: {
			Class:  event.ClassLog,
			Action: "event log cleared",
			// 104 writes no SID beside the name, but the System block carries
			// the sid of whoever asked for the clear, and on this event that is
			// the actor rather than the service that wrote the record.
			User: Account{Name: "SubjectUserName", Domain: "SubjectDomainName", SID: "SecurityUserID"},
		},
		1102: {
			Class:  event.ClassLog,
			Action: "audit log cleared",
			User:   securitySubject,
		},
	},

	scm: {
		7036: {
			// Service Control Manager writes no named fields. The service is in
			// param1 and its new state in param2, because the provider's
			// manifest declares them as positional parameters of a message.
			Class:    event.ClassService,
			Action:   "service state changed",
			Activity: "param2",
			Entities: []Ref{{Kind: event.KindService, Field: "param1", Role: "subject"}},
		},
	},

	powersh: {
		4104: {
			// The script text itself is in ScriptBlockText, which the rules
			// match against and the report shows at level three. The account is
			// the SID in the System block: PowerShell logs under the identity
			// that ran it.
			Class:    event.ClassProcess,
			Action:   "PowerShell script block logged",
			User:     Account{SID: "SecurityUserID"},
			Entities: []Ref{{Kind: event.KindFile, Field: "Path", Role: "script"}},
		},
	},
}

// Lookup returns what an event id means, and whether anything is known about
// it. A miss is not a failure: most of the 31,243 records in the corpus are RPC
// trace events that no table covers, and they still belong in the timeline with
// their raw fields.
func Lookup(producer string, id int) (Mapping, bool) {
	byID, ok := mappings[producer]
	if !ok {
		return Mapping{}, false
	}
	m, ok := byID[id]
	return m, ok
}

// Classify fills in what the record means. An event with no mapping keeps its
// class unknown and its raw fields, which is what an honest "I read this but I
// do not know what it is" looks like.
func Classify(f Flat, e *event.Event) {
	m, ok := Lookup(f.Producer, f.EventID)
	if !ok {
		return
	}

	e.Class = m.Class
	e.Action = m.Action
	if m.Activity != "" {
		if v := f.Fields[m.Activity]; !Unavailable(v) {
			e.Activity = v
		}
	}

	e.Process = processOf(f, m.Actor)
	e.Parent = processOf(f, m.Parent)
	e.Target = processOf(f, m.Target)

	e.User = accountOf(f, m.User)
	e.Add(event.KindAccount, "actor", e.User)
	e.Add(event.KindSession, "actor", valueOf(f, m.User.Logon))
	e.Add(event.KindAccount, "subject", accountOf(f, m.Subject))
	e.Add(event.KindSession, "subject", valueOf(f, m.Subject.Logon))

	for _, r := range m.Entities {
		e.Add(r.Kind, r.Role, valueOf(f, r.Field))
	}
}

func processOf(f Flat, p Proc) event.Process {
	return event.Process{
		Image:       valueOf(f, p.Image),
		CommandLine: valueOf(f, p.CommandLine),
		PID:         valueOf(f, p.PID),
		GUID:        valueOf(f, p.GUID),
	}
}

// accountOf renders an account the way Windows writes one itself: DOMAIN\user
// when the record holds both halves, and whichever half it holds when it does
// not. Joining two recorded values is a presentation choice and not a
// deduction, so the result is still Observed; nothing here is worked out.
func accountOf(f Flat, a Account) event.Field {
	name := text(f, a.Name)
	domain := text(f, a.Domain)
	switch {
	case name != "" && domain != "":
		return event.Seen(domain + `\` + name)
	case name != "":
		return event.Seen(name)
	case text(f, a.SID) != "":
		// A SID with no name is still an identity, and on some events it is the
		// only one written.
		return event.Seen(text(f, a.SID))
	}
	return event.Field{}
}

func valueOf(f Flat, field string) event.Field {
	if v := text(f, field); v != "" {
		return event.Seen(v)
	}
	return event.Field{}
}

// text reads a field and treats the provider's blanks as absent, so that a "-"
// never becomes an entity. The raw fields keep the value either way.
func text(f Flat, field string) string {
	if field == "" {
		return ""
	}
	v := f.Fields[field]
	if Unavailable(v) {
		return ""
	}
	return strings.TrimSpace(v)
}
