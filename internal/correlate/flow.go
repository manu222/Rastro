package correlate

import (
	"fmt"
	"strings"

	"github.com/manu222/rastro/internal/event"
)

// The join between what the host saw and what the wire saw.
//
// Each half of a connection is recorded by something that cannot see the other.
// Zeek writes how many bytes crossed, how long it lasted and what its analysers
// made of it, and has no idea which program opened it: a packet carries no
// process. Sysmon writes the program, the account and the command line, and
// records nothing about what was actually sent. Neither half answers "a
// seven-kilobyte executable came down from 10.0.5.13 — who asked for it", and
// together they do.
//
// What joins them is the five-tuple: the two addresses, the two ports and the
// protocol. Not the time. That is worth stating plainly because time is the
// obvious key and it is the wrong one. In the corpus this was written for, the
// two clocks differ by nineteen hours on most Sysmon event types and by a
// hundred and fifteen on the two that record network activity — which are the
// only two that matter here. A join on a time window would have found nothing
// and the code would have looked broken. On the five-tuple it finds 87 to 97
// per cent of the flows, in all seven campaigns.
//
// The tuple is matched as written, in one direction only. Reversing it when the
// direct match fails was measured and is not worth doing: it recovers 2 of 96
// in the first campaign and 4 of 861 in the fifth, under one per cent, and the
// records it recovers are the ones where the two sources disagree about which
// end opened the connection — which is a thing to report, not to paper over.
//
// And a tuple can repeat. A port is reused, and 14 of the 881 flows in the
// fifth campaign share a tuple with another. Where that happens nothing is
// attributed: the natural tiebreak is the time, and the clocks are what we have
// just established cannot be trusted between the two sources. An ambiguous
// tuple is reported as ambiguous, the same way a lineage that cannot reach a
// root says so instead of inventing one.

// Flow is one connection as the network recorded it, reduced to what a finding
// needs.
type Flow struct {
	// UID is Zeek's own identifier for the flow. It is carried through so that
	// an analyst can find every other record of the same connection in the
	// evidence — the request, the file, the certificate — without this package
	// having to join them itself.
	UID      string
	Service  string
	State    string
	Sent     string
	Received string
	Duration string

	Origin event.Origin
}

// Host is one connection as the host recorded it.
type Host struct {
	Image       string
	CommandLine string
	PID         string
	GUID        string
	User        string

	// Remote is the far end, the way an analyst says it: 10.0.5.13:8080.
	// Which end that is comes out of the record rather than out of a guess —
	// Sysmon writes whether the connection was initiated here, and on an
	// inbound one the far end is the source.
	Remote   string
	Protocol string
	// Key is the five-tuple this record was filed under, so that the flow can
	// be looked up again without rebuilding it.
	Key string

	Origin event.Origin
}

// Connection is what the other source said about the same connection.
//
// One of Flow and Process is filled, never both: a host record gains the flow
// and a network record gains the process. Every value in it is deduced — the
// two records were joined by this package, not by anything in the evidence —
// so each carries the sentence that explains the join.
type Connection struct {
	Flow    *Flow
	Process event.Process
	User    event.Field
	// Why explains the join in a sentence an analyst can check against the
	// evidence.
	Why string
	// Unresolved says why there is nothing, when there is nothing: the other
	// half is not in the evidence, or there is more than one candidate and
	// choosing between them would be a guess.
	Unresolved string
}

// Found reports whether the other half was there.
func (c Connection) Found() bool { return c.Flow != nil || !c.Process.Empty() }

// observeFlow records a Zeek connection record.
func (ix *Index) observeFlow(e *event.Event, key string) {
	if ix.Limits.MaxFlows > 0 && len(ix.flows)+ix.DroppedFlows >= ix.Limits.MaxFlows {
		ix.DroppedFlows++
		return
	}
	if uid := e.Raw["uid"]; uid != "" {
		if prev, dup := ix.connByUID[uid]; dup && prev != key {
			ix.connByUID[uid] = "" // ambiguous: keyOf says so
		} else {
			ix.connByUID[uid] = key
		}
	}
	ix.flows[key] = append(ix.flows[key], &Flow{
		UID:      e.Raw["uid"],
		Service:  e.Raw["service"],
		State:    e.Raw["conn_state"],
		Sent:     e.Raw["orig_bytes"],
		Received: e.Raw["resp_bytes"],
		Duration: e.Raw["duration"],
		Origin:   e.Origin,
	})
}

// observeHostConn records a host's own account of a connection.
func (ix *Index) observeHostConn(e *event.Event, key string) {
	if ix.Limits.MaxFlows > 0 && len(ix.hostConns)+ix.DroppedFlows >= ix.Limits.MaxFlows {
		ix.DroppedFlows++
		return
	}
	h := &Host{
		Image:       e.Process.Image.Value,
		CommandLine: e.Process.CommandLine.Value,
		PID:         e.Process.PID.Value,
		GUID:        e.Process.GUID.Value,
		User:        e.User.Value,
		Remote:      remoteEnd(e),
		Protocol:    e.Raw["Protocol"],
		Key:         key,
		Origin:      e.Origin,
	}
	// A record that names no program is no use as the answer to "who opened
	// this", and recording it would turn a miss into an ambiguity.
	if h.Image == "" {
		return
	}
	ix.hostConns[key] = append(ix.hostConns[key], h)

	// And the same record filed under the process that opened it, which is
	// what lets a finding about a process say what that process reached.
	//
	// Only by the identifier that is unique over time. A pid is reused, and
	// attributing one process's connections to whoever held its number an hour
	// later is the same mistake as walking a lineage by pid — which is the
	// mistake this package was built around not making.
	if h.GUID != "" {
		ix.byProcess[h.GUID] = append(ix.byProcess[h.GUID], h)
	}
}

// remoteEnd names the far end of a connection.
//
// Sysmon writes Initiated, which says whether this machine opened it. On an
// outbound connection the far end is the destination and on an inbound one it
// is the source, and reading that out of the record is not a judgement: the
// provider wrote it down.
func remoteEnd(e *event.Event) string {
	ip, port := e.Raw["DestinationIp"], e.Raw["DestinationPort"]
	if strings.EqualFold(strings.TrimSpace(e.Raw["Initiated"]), "false") {
		ip, port = e.Raw["SourceIp"], e.Raw["SourcePort"]
	}
	if ip == "" {
		return ""
	}
	if port == "" {
		return ip
	}
	return ip + ":" + port
}

// Connection answers what the other source saw of the same connection.
func (ix *Index) Connection(e *event.Event) Connection {
	key, fromNetwork, via, ok, unresolved := ix.keyOf(e)
	if !ok {
		return Connection{Unresolved: unresolved}
	}
	where := describe(key)
	if via != "" {
		where += " (" + via + ")"
	}

	if fromNetwork {
		switch candidates := ix.hostConns[key]; len(candidates) {
		case 0:
			return Connection{Unresolved: "no host record in this evidence names a process for " + where}
		case 1:
			h := candidates[0]
			why := "the only process this evidence records opening " + where
			c := Connection{
				Process: event.Process{
					Image:       event.Deduced(h.Image, why),
					CommandLine: event.Deduced(h.CommandLine, why),
					PID:         event.Deduced(h.PID, why),
					GUID:        event.Deduced(h.GUID, why),
				},
				Why: why,
			}
			if h.User != "" {
				c.User = event.Deduced(h.User, why)
			}
			return c
		default:
			return Connection{Unresolved: fmt.Sprintf(
				"%d processes are recorded opening %s, and the only way to choose between them "+
					"would be the time, which these two sources do not agree about",
				len(candidates), where)}
		}
	}

	switch candidates := ix.flows[key]; len(candidates) {
	case 0:
		return Connection{Unresolved: "the network evidence holds no flow for " + where}
	case 1:
		return Connection{
			Flow: candidates[0],
			Why:  "the only flow in this evidence for " + where,
		}
	default:
		return Connection{Unresolved: fmt.Sprintf(
			"%d flows in the network evidence share %s, and the only way to choose between them "+
				"would be the time, which these two sources do not agree about",
			len(candidates), where)}
	}
}

// keyOf is tupleOf with one more way in. A Zeek record with endpoints and no
// protocol is placed through its uid, which Zeek writes identically in
// conn.log, so that hop is read and not deduced. Measured: the six
// application/x-dosexec rows of files.log in the compound corpus have no proto;
// all six reach a tcp conn row by uid and from there exactly one Sysmon 3.
//
// Before this, such a record came back as an empty Connection with no reason,
// and a finding on it said nothing about who asked for the file — a blank that
// reads as "nobody did".
func (ix *Index) keyOf(e *event.Event) (key string, fromNetwork bool, via string, ok bool, unresolved string) {
	if key, fromNetwork, ok = tupleOf(e); ok {
		return key, fromNetwork, "", true, ""
	}
	if e.Raw["id.orig_h"] == "" {
		return "", false, "", false, "" // not a network record: nothing to say
	}
	uid := e.Raw["uid"]
	k, found := ix.connByUID[uid]
	switch {
	case uid == "":
		return "", true, "", false, "the network record names no protocol and no Zeek uid to find its connection by"
	case !found:
		return "", true, "", false, "the network record names no protocol, and conn.log holds no connection with Zeek uid " + uid
	case k == "":
		return "", true, "", false, "Zeek uid " + uid + " names more than one connection in conn.log"
	}
	return k, true, "through the conn.log row with Zeek uid " + uid, true, ""
}

// tupleOf reads the five-tuple off a record and says which side of the join the
// record is on.
//
// Which side it is on is read off the field names rather than off the label the
// reader gave it. A record carrying id.orig_h is Zeek's account of a flow
// whatever anything else says, and one carrying SourceIp and DestinationIp is a
// host's. That is one less thing that can be got wrong by a reader somewhere
// else labelling evidence differently.
func tupleOf(e *event.Event) (key string, fromNetwork bool, ok bool) {
	if h := e.Raw["id.orig_h"]; h != "" {
		return tuple(h, e.Raw["id.orig_p"], e.Raw["id.resp_h"], e.Raw["id.resp_p"], e.Raw["proto"])
	}
	if h := e.Raw["SourceIp"]; h != "" {
		k, _, ok := tuple(h, e.Raw["SourcePort"], e.Raw["DestinationIp"], e.Raw["DestinationPort"], e.Raw["Protocol"])
		return k, false, ok
	}
	return "", false, false
}

func tuple(sip, sport, dip, dport, proto string) (string, bool, bool) {
	if sip == "" || sport == "" || dip == "" || dport == "" || proto == "" {
		return "", true, false
	}
	return strings.ToLower(sip + "\x00" + sport + "\x00" + dip + "\x00" + dport + "\x00" + proto), true, true
}

// describe writes a tuple the way an analyst would say it out loud, because it
// ends up in a sentence in a report.
func describe(key string) string {
	p := strings.Split(key, "\x00")
	if len(p) != 5 {
		return key
	}
	return fmt.Sprintf("%s:%s to %s:%s over %s", p[0], p[1], p[2], p[3], p[4])
}

// Flows reports how much of each half the index holds, for the diagnostic view.
func (ix *Index) Flows() (network, host int) {
	return len(ix.flows), len(ix.hostConns)
}

// Sighting is one connection a process opened, with what the network made of
// it when the network saw it too.
type Sighting struct {
	Remote   string
	Protocol string
	// Flow is nil when the network evidence holds nothing for this connection,
	// which is a different thing from the connection not happening: the
	// capture may simply not cover that interface or that minute.
	Flow   *Flow
	Origin event.Origin
}

// Reach is what a process did on the network, for a finding that is about the
// process rather than about one of its connections.
//
// This is where the join earns its place. A finding says a program opened
// lsass; what an analyst asks next is where that program came from and where it
// went, and the second half of that question is answered by records the finding
// never touches. Nothing here is new detection — it is the same evidence,
// attached to the finding that makes it worth reading.
type Reach struct {
	// Total is how many connections this process opened in the evidence.
	Total int
	// OnWire is how many of those the network recorded as well.
	OnWire    int
	Sightings []Sighting
	// Unresolved says why there is nothing to show, when there is nothing.
	Unresolved string
}

// Network reports the connections the event's acting process opened.
func (ix *Index) Network(e *event.Event) Reach {
	guid := e.Process.GUID.Value
	if guid == "" {
		// Without an identifier that is unique over time there is nothing to
		// ask with, and asking by pid would answer with another process's
		// connections. Said rather than left blank, because a blank reads as
		// "this process opened nothing".
		return Reach{Unresolved: "the record names no process identifier, and a pid is reused"}
	}
	opened := ix.byProcess[guid]
	if len(opened) == 0 {
		return Reach{}
	}

	r := Reach{Total: len(opened)}
	for _, h := range opened {
		s := Sighting{Remote: h.Remote, Protocol: h.Protocol, Origin: h.Origin}
		// Only an unambiguous flow is attached. Two flows sharing a tuple are
		// two candidates, and the tiebreak would be the time.
		if candidates := ix.flows[h.Key]; len(candidates) == 1 {
			s.Flow = candidates[0]
			r.OnWire++
		}
		r.Sightings = append(r.Sightings, s)
	}
	return r
}
