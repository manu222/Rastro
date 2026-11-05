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
		Origin:      e.Origin,
	}
	// A record that names no program is no use as the answer to "who opened
	// this", and recording it would turn a miss into an ambiguity.
	if h.Image == "" {
		return
	}
	ix.hostConns[key] = append(ix.hostConns[key], h)
}

// Connection answers what the other source saw of the same connection.
func (ix *Index) Connection(e *event.Event) Connection {
	key, fromNetwork, ok := tupleOf(e)
	if !ok {
		return Connection{}
	}
	where := describe(key)

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
