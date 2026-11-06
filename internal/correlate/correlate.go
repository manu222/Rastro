// Package correlate answers the question a finding leaves open.
//
// "A process opened lsass with read rights" is a detection. It is not yet
// information, because opening lsass as SYSTEM is what half the operating
// system does all day. What makes it a finding is the three questions after it:
// how did this get to SYSTEM, who was behind it, and from where.
//
// All three are answered by walking up. A Sysmon process creation names its
// parent, the account it ran as and the logon session it ran in; the process
// that opened lsass names none of those, but it does name itself, and its
// creation is somewhere in the evidence. Following that chain gives the lineage,
// the point where the account changed — which is what "how did it get to
// SYSTEM" means in practice — and the logon session, which a 4624 turns into a
// type, an address and a workstation.
//
// Nothing here guesses. Every value this package produces is either read from a
// record or marked as deduced with the record it was deduced from written into
// it, so a report can show the chain and let the analyst decide whether to
// believe it. Where the chain breaks — because the creating event is not in the
// evidence — it says so and stops. An unknown ancestor stays unknown.
package correlate

import (
	"fmt"
	"strings"

	"github.com/manu222/rastro/internal/event"
)

// Limits bound what the index is allowed to cost.
//
// The index does not hold the evidence. It holds only the records that can be
// an ancestor of something — process creations and logons — which over the
// pinned corpus is about five hundred records out of 31,243. That is the
// difference between an index that fits in memory on a real case and one that
// is the case itself: a million events at the measured 2.3 KB each is 2.3 GB,
// and a million events contain nothing like a million process creations.
type Limits struct {
	// MaxProcesses stops recording creations after this many. Zero means no
	// limit, which is only reasonable in tests.
	MaxProcesses int
	// MaxLogons does the same for logon sessions.
	MaxLogons int
	// MaxDepth stops walking a lineage after this many steps, so that a cycle
	// in damaged evidence cannot spin for ever.
	MaxDepth int
	// MaxFlows bounds each half of the connection join. A busy day of network
	// evidence is many more flows than process creations, which is why it has
	// a limit of its own rather than sharing one.
	MaxFlows int
}

// DefaultLimits are generous for real evidence and small enough that a
// malformed file cannot exhaust the machine.
func DefaultLimits() Limits {
	return Limits{MaxProcesses: 2_000_000, MaxLogons: 500_000, MaxDepth: 32, MaxFlows: 20_000_000}
}

// Index holds what can be an ancestor.
type Index struct {
	Limits Limits

	// byGUID is the reliable path: a process identifier that is unique over
	// time, so the creation it finds is the creation of this process and not of
	// whoever held the same number an hour earlier.
	byGUID map[string]*Process
	// byPIDHost is the fallback for evidence with no such identifier — Windows'
	// own 4688, auditd — and it is deliberately awkward to use. See Creator.
	byPIDHost map[string][]*Process

	logons map[string]*Logon

	// The two halves of the connection join, each keyed by the five-tuple. See
	// flow.go for why that is the key and the time is not.
	flows     map[string][]*Flow
	hostConns map[string][]*Host
	// byProcess is the same host records filed under the process that opened
	// them, so that a finding about a process can say what it reached.
	byProcess map[string][]*Host
	// connByUID files each conn.log tuple under Zeek's uid. http, files and ssl
	// carry the same uid and the four endpoints but not the protocol, so
	// tupleOf alone cannot place them. 0 duplicate uids in the 2,711 conn rows
	// of the compound corpus; a duplicate is still marked, because an
	// overwrite here would be silent.
	connByUID map[string]string
	// peByFUID is pe.log filed under Zeek's file id, which files.log writes
	// beside the flow's uid. A list, so that a repeated id is seen.
	peByFUID map[string][]*Executable

	// Dropped counts what the limits refused to record, so that a lineage that
	// breaks because of a limit can say that rather than look like missing
	// evidence.
	Dropped      int
	DroppedFlows int
}

// Process is a creation, reduced to what a lineage needs.
type Process struct {
	Host        string
	GUID        string
	PID         string
	Image       string
	CommandLine string
	// ParentGUID and ParentPID point at the next step up.
	ParentGUID  string
	ParentPID   string
	ParentImage string
	// User and LogonID are what the creation recorded. Either can be empty:
	// Windows' own 4688 names the account that asked for the creation, Sysmon
	// names the account the process runs as, and neither always has both.
	User    string
	LogonID string
	// Integrity is Sysmon's IntegrityLevel. It is how a lineage shows the step
	// where something stopped being an ordinary user process.
	Integrity string

	Origin event.Origin
	Time   int64 // unix nanoseconds, for ordering and for the pid fallback
}

// Logon is a session, reduced the same way.
type Logon struct {
	Host        string
	ID          string
	User        string
	Type        string
	Address     string
	Workstation string
	Process     string

	Origin event.Origin
	Time   int64
}

// New returns an empty index.
func New() *Index {
	return &Index{
		Limits:    DefaultLimits(),
		byGUID:    map[string]*Process{},
		byPIDHost: map[string][]*Process{},
		logons:    map[string]*Logon{},
		flows:     map[string][]*Flow{},
		hostConns: map[string][]*Host{},
		byProcess: map[string][]*Host{},
		connByUID: map[string]string{},
		peByFUID:  map[string][]*Executable{},
	}
}

// Observe records an event if it can be an ancestor of something, and ignores
// it otherwise.
//
// This is called for every record of the evidence, so what it does for the
// 29,523 records that are neither a creation nor a logon is one comparison.
func (ix *Index) Observe(e *event.Event) {
	switch e.Class {
	case event.ClassProcess:
		if e.Action == "process created" {
			ix.observeProcess(e)
		}
	case event.ClassAuth:
		if e.Action == "logon" {
			ix.observeLogon(e)
		}
	case event.ClassFile:
		if e.Action == "executable analysed on the wire" {
			ix.observePE(e)
		}
	case event.ClassNetwork:
		// Only the two records that are an account of a connection: Zeek's
		// conn.log row and the host's own network-connection event. A DNS
		// record carries the same five-tuple and is not an account of the
		// flow, so indexing it would put a query where a connection belongs.
		switch e.Action {
		case "connection":
			if key, _, ok := tupleOf(e); ok {
				ix.observeFlow(e, key)
			}
		case "network connection":
			if key, _, ok := tupleOf(e); ok {
				ix.observeHostConn(e, key)
			}
		}
	}
}

func (ix *Index) observeProcess(e *event.Event) {
	if ix.Limits.MaxProcesses > 0 && len(ix.byGUID)+ix.Dropped >= ix.Limits.MaxProcesses {
		ix.Dropped++
		return
	}
	p := &Process{
		Host:        e.Host.Value,
		GUID:        e.Process.GUID.Value,
		PID:         e.Process.PID.Value,
		Image:       e.Process.Image.Value,
		CommandLine: e.Process.CommandLine.Value,
		ParentGUID:  e.Parent.GUID.Value,
		ParentPID:   e.Parent.PID.Value,
		ParentImage: e.Parent.Image.Value,
		User:        e.User.Value,
		LogonID:     e.Raw["LogonId"],
		Integrity:   e.Raw["IntegrityLevel"],
		Origin:      e.Origin,
		Time:        e.Time.UnixNano(),
	}
	if p.LogonID == "" {
		p.LogonID = e.Raw["SubjectLogonId"]
	}
	if p.GUID != "" {
		ix.byGUID[p.GUID] = p
	}
	if p.PID != "" {
		key := p.Host + "\x00" + p.PID
		ix.byPIDHost[key] = append(ix.byPIDHost[key], p)
	}
}

func (ix *Index) observeLogon(e *event.Event) {
	id := e.Raw["TargetLogonId"]
	if id == "" {
		return
	}
	if ix.Limits.MaxLogons > 0 && len(ix.logons) >= ix.Limits.MaxLogons {
		ix.Dropped++
		return
	}
	l := &Logon{
		Host:        e.Host.Value,
		ID:          id,
		Type:        e.Raw["LogonType"],
		Address:     e.Raw["IpAddress"],
		Workstation: e.Raw["WorkstationName"],
		Process:     e.Raw["ProcessName"],
		Origin:      e.Origin,
		Time:        e.Time.UnixNano(),
	}
	// The account the session was created for, which is the Target side of a
	// 4624 and not the Subject side that asked for it.
	if name := e.Raw["TargetUserName"]; name != "" {
		if domain := e.Raw["TargetDomainName"]; domain != "" {
			l.User = domain + `\` + name
		} else {
			l.User = name
		}
	}
	ix.logons[e.Host.Value+"\x00"+id] = l
}

// Creator returns the creation of a process, and how certain that answer is.
//
// By identifier it is certain: the identifier is unique over time, which is why
// Sysmon emits one. By process id it is a guess, and the guess is only offered
// when there is exactly one candidate that was created before the event asking.
// More than one and the answer is no answer, because attributing an action to
// whoever held a recycled number earlier is how a report accuses the wrong
// person.
func (ix *Index) Creator(e *event.Event) (*Process, string, bool) {
	if guid := e.Process.GUID.Value; guid != "" {
		if p, ok := ix.byGUID[guid]; ok {
			return p, fmt.Sprintf("the process creation carrying the same ProcessGuid, record %d of %s",
				p.Origin.Record, p.Origin.Path), true
		}
		// The identifier is there and its creation is not in the evidence. That
		// is a fact about the evidence and not a reason to fall back to a
		// weaker method: the pid of this event belongs to the same process, so
		// a pid lookup would find the same gap or, worse, a different process.
		return nil, "", false
	}

	pid := e.Process.PID.Value
	if pid == "" {
		return nil, "", false
	}
	var found *Process
	when := e.Time.UnixNano()
	for _, p := range ix.byPIDHost[e.Host.Value+"\x00"+pid] {
		if p.Time > when {
			continue
		}
		if found != nil {
			return nil, "", false
		}
		found = p
	}
	if found == nil {
		return nil, "", false
	}
	return found, fmt.Sprintf(
		"the only process creation with pid %s on %s before this event, record %d of %s",
		pid, e.Host.Value, found.Origin.Record, found.Origin.Path), true
}

// Step is one process of a lineage, with how it was reached.
type Step struct {
	Process *Process
	// Why is empty on the step the event itself names, and otherwise says which
	// record the step was reached through.
	Why string
}

// Ancestry walks from the process an event names up to the oldest ancestor the
// evidence holds.
//
// The walk stops where the evidence does. A chain that ends because the parent's
// creation was never recorded is not a chain that ends at the root, and the
// caller can tell the difference: Complete reports which it was.
func (ix *Index) Ancestry(e *event.Event) (steps []Step, complete bool) {
	start, why, ok := ix.Creator(e)
	if !ok {
		return nil, false
	}
	steps = append(steps, Step{Process: start, Why: why})

	current := start
	for depth := 1; ix.Limits.MaxDepth == 0 || depth < ix.Limits.MaxDepth; depth++ {
		next, why, ok := ix.parentOf(current)
		if !ok {
			// No parent recorded. Either this is the root of what the evidence
			// holds, or the record is simply not here. Saying "the lineage ends
			// here" would be claiming the first when it may be the second.
			return steps, current.ParentGUID == "" && current.ParentPID == ""
		}
		if next == current {
			return steps, false
		}
		steps = append(steps, Step{Process: next, Why: why})
		current = next
	}
	return steps, false
}

func (ix *Index) parentOf(p *Process) (*Process, string, bool) {
	if p.ParentGUID != "" {
		parent, ok := ix.byGUID[p.ParentGUID]
		if !ok {
			return nil, "", false
		}
		return parent, fmt.Sprintf("the parent named by record %d of %s",
			p.Origin.Record, p.Origin.Path), true
	}
	if p.ParentPID == "" {
		return nil, "", false
	}
	var found *Process
	for _, candidate := range ix.byPIDHost[p.Host+"\x00"+p.ParentPID] {
		if candidate.Time > p.Time {
			continue
		}
		if found != nil {
			return nil, "", false
		}
		found = candidate
	}
	if found == nil {
		return nil, "", false
	}
	return found, fmt.Sprintf("the only process creation with pid %s on %s before it, record %d of %s",
		p.ParentPID, p.Host, found.Origin.Record, found.Origin.Path), true
}

// Account resolves who was behind an event.
//
// An event that names an account is believed and the value stays observed. An
// event that names none — which is three Sysmon events out of four — is resolved
// through its own creation, and the result is marked as deduced with the record
// it came from. The distinction is the whole point: an incident built out of
// observations is worth more than one built out of deductions, and a report that
// cannot tell them apart is a report that cannot be checked.
func (ix *Index) Account(e *event.Event) event.Field {
	if e.User.Known() {
		return e.User
	}
	creator, why, ok := ix.Creator(e)
	if !ok || creator.User == "" {
		return event.Field{}
	}
	return event.Deduced(creator.User, "the account the acting process was created as, from "+why)
}

// Unresolved explains why no account could be worked out.
//
// A report with a blank where a name should be tells the reader nothing about
// whether the tool failed, the evidence is short, or the record genuinely has
// no owner. Those are three different situations and only one of them is worth
// going to look at, so the reason is said rather than left out.
func (ix *Index) Unresolved(e *event.Event) string {
	if e.User.Known() {
		return ""
	}
	if guid := e.Process.GUID.Value; guid != "" {
		p, ok := ix.byGUID[guid]
		switch {
		case !ok:
			return "the creation of this process is not in the evidence"
		case p.User == "":
			return "the process creation records no account either"
		}
		return ""
	}
	pid := e.Process.PID.Value
	if pid == "" {
		return "the record names no process to trace it through"
	}
	candidates := 0
	when := e.Time.UnixNano()
	for _, p := range ix.byPIDHost[e.Host.Value+"\x00"+pid] {
		if p.Time <= when {
			candidates++
		}
	}
	switch candidates {
	case 0:
		return "no process with pid " + pid + " was recorded being created on " + e.Host.Value
	case 1:
		return "the process creation records no account either"
	default:
		return fmt.Sprintf("%d processes have held pid %s on %s, and guessing between them is how a report blames the wrong one",
			candidates, pid, e.Host.Value)
	}
}

// Session resolves the logon the event's process was running in.
func (ix *Index) Session(e *event.Event) (*Logon, event.Field) {
	id := e.Raw["LogonId"]
	source := "the logon session this record names"
	if id == "" {
		creator, why, ok := ix.Creator(e)
		if !ok || creator.LogonID == "" {
			return nil, event.Field{}
		}
		id = creator.LogonID
		source = "the logon session the acting process was created in, from " + why
	}
	l := ix.logons[e.Host.Value+"\x00"+id]
	if l == nil {
		// The session id is known and the logon that opened it is not in the
		// evidence. Returning the id alone is still worth something: it groups
		// everything that happened in that session, which is most of what a
		// timeline needs.
		return nil, event.Deduced(id, source)
	}
	return l, event.Deduced(l.User, source+", opened by record "+
		fmt.Sprintf("%d of %s", l.Origin.Record, l.Origin.Path))
}

// Entry resolves where a lineage came from, which is a different question from
// where its last process was running.
//
// A process that opens lsass as SYSTEM runs in session 0x3e7, the one the
// operating system itself uses. Reporting that as the answer to "where did this
// come from" is true and useless. The session worth naming is the oldest one in
// the lineage that an actual logon opened, because that is the one with a type,
// an address and a workstation on it — the remote desktop, the network share,
// the person at the keyboard.
//
// The walk goes from the oldest ancestor downwards and stops at the first
// session the evidence can explain.
func (ix *Index) Entry(steps []Step) (*Logon, event.Field) {
	for i := len(steps) - 1; i >= 0; i-- {
		p := steps[i].Process
		if p.LogonID == "" {
			continue
		}
		l := ix.logons[p.Host+"\x00"+p.LogonID]
		if l == nil {
			continue
		}
		return l, event.Deduced(l.User, fmt.Sprintf(
			"the session %s was created in, opened by record %d of %s",
			shortImage(p.Image), l.Origin.Record, l.Origin.Path))
	}
	return nil, event.Field{}
}

func shortImage(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// Escalation reports the step of a lineage where the account changed.
//
// This is the answer to "how did it get to SYSTEM". It names the two accounts
// and the process that sits between them, and it does not call it an escalation
// or a compromise: a service starting as SYSTEM under services.exe is the same
// shape as a token theft, and which one it was is the analyst's call and not a
// function's. What this does is point at the exact record where the answer
// changes.
type Escalation struct {
	From *Process
	To   *Process
	// FromUser and ToUser are the accounts either side of the change.
	FromUser string
	ToUser   string
}

// Escalations walks a lineage from the oldest ancestor down and reports every
// point where the account is not the one above it.
func Escalations(steps []Step) []Escalation {
	var out []Escalation
	// steps are ordered from the event's own process upwards, so walking them
	// backwards is walking forwards in time.
	for i := len(steps) - 1; i > 0; i-- {
		above, below := steps[i].Process, steps[i-1].Process
		if above.User == "" || below.User == "" {
			continue
		}
		if strings.EqualFold(above.User, below.User) {
			continue
		}
		out = append(out, Escalation{
			From: above, To: below,
			FromUser: above.User, ToUser: below.User,
		})
	}
	return out
}

// Size reports what the index is holding, for the line of the report that says
// what the analysis cost.
func (ix *Index) Size() (processes, logons int) {
	return len(ix.byGUID), len(ix.logons)
}
