// Package evtx reads Windows event log files and hands their records to the
// rest of the pipeline.
//
// There is very little judgement in here on purpose. Everything that had to be
// decided — how a record is flattened, how a provider's values are restored,
// what an event carries — lives in packages that can be tested without a parser
// and were. What is left is the mechanical part: open the file, walk the
// chunks, convert what the library returns into plain Go maps, and keep going
// when something is damaged.
//
// That last point is not a detail. Evidence arrives broken. A log pulled off a
// machine mid-incident, a disk image with a bad sector, a file an attacker
// truncated on the way out — all of them produce a chunk that will not parse,
// and giving up on the whole file because of one of them would throw away
// everything after it. A damaged chunk is counted and skipped, and the count
// goes in the report, because "I read 40,000 of the 41,000 records in this
// file" is information the analyst needs and silence is not.
package evtx

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Velocidex/ordereddict"
	velocievtx "www.velocidex.com/golang/evtx"

	"github.com/manu222/rastro/internal/event"
	"github.com/manu222/rastro/internal/normalise"
	"github.com/manu222/rastro/internal/winevent"
)

// Limits bound what one file is allowed to cost. Evidence is attacker-chosen
// input and a parser is the place where that becomes dangerous: the defence is
// not to trust the file's own idea of how big it is.
type Limits struct {
	// MaxRecords stops after this many records in a single file. Zero means no
	// limit, which is only reasonable in tests.
	MaxRecords int
	// MaxBytes refuses a file larger than this before opening it.
	MaxBytes int64
	// Deadline stops the walk once it has run this long.
	Deadline time.Duration
}

// DefaultLimits are deliberately generous: large enough for real evidence,
// small enough that a malformed file cannot run until the machine dies. They
// are numbers to be revisited with measurements, not constants of nature.
func DefaultLimits() Limits {
	return Limits{
		MaxRecords: 5_000_000,
		MaxBytes:   4 << 30, // 4 GiB
		Deadline:   30 * time.Minute,
	}
}

// Stats is what the reader can say about a file afterwards.
type Stats struct {
	Records int
	// DamagedChunks is how many chunks failed to parse and were skipped.
	DamagedChunks int
	// Unreadable is how many records parsed but could not be turned into an
	// event.
	Unreadable int
	// FirstFailure is why the first unreadable record failed. A count on its
	// own is useless: "31,243 records unreadable" gives whoever reads it
	// nowhere to start, and the first time this reader ran it printed exactly
	// that. One cause, kept, costs nothing and turns the number into a lead.
	FirstFailure error
	// SkippedFields counts fields that could not be rendered and were left out
	// of records that were otherwise kept.
	SkippedFields int
	// Stopped reports that a limit cut the walk short, so that a partial read
	// is never mistaken for a complete one.
	Stopped string
}

// Reader walks one evidence directory's worth of Windows event logs.
type Reader struct {
	Normaliser *normalise.Normaliser
	Limits     Limits
	// Root is the directory the analysis was given. Paths recorded on events
	// are relative to it, so a report does not carry the directory layout of
	// whoever ran the tool.
	Root string
}

// New returns a reader with the default tables and limits.
func New(root string) *Reader {
	return &Reader{
		Normaliser: normalise.Default(),
		Limits:     DefaultLimits(),
		Root:       root,
	}
}

// ReadFile walks one file, calling emit once per record.
//
// emit returning an error stops the walk and the error is returned as is: that
// is how a consumer says "enough", and it is also how a limit further down the
// pipeline reaches up here.
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

	chunks, err := velocievtx.GetChunks(fd)
	if err != nil {
		return stats, fmt.Errorf("%s is not a readable event log: %w", rel, err)
	}

	start := time.Now()
	for _, chunk := range chunks {
		records, err := chunk.Parse(0)
		if err != nil {
			stats.DamagedChunks++
			continue
		}

		for _, rec := range records {
			if r.Limits.MaxRecords > 0 && stats.Records >= r.Limits.MaxRecords {
				stats.Stopped = fmt.Sprintf("record limit of %d reached", r.Limits.MaxRecords)
				return stats, nil
			}
			if r.Limits.Deadline > 0 && time.Since(start) > r.Limits.Deadline {
				stats.Stopped = fmt.Sprintf("deadline of %s reached", r.Limits.Deadline)
				return stats, nil
			}

			dict, ok := rec.Event.(*ordereddict.Dict)
			if !ok {
				stats.Unreadable++
				if stats.FirstFailure == nil {
					stats.FirstFailure = fmt.Errorf(
						"record %d: the parser returned %T, not an event", rec.Header.RecordID, rec.Event)
				}
				continue
			}

			ev, skipped, err := r.build(dict, rel, int64(rec.Header.RecordID))
			if err != nil {
				stats.Unreadable++
				if stats.FirstFailure == nil {
					stats.FirstFailure = fmt.Errorf("record %d: %w", rec.Header.RecordID, err)
				}
				continue
			}
			stats.Records++
			stats.SkippedFields += skipped
			if err := emit(ev); err != nil {
				return stats, err
			}
		}
	}
	return stats, nil
}

// build turns one parsed record into an event.
func (r *Reader) build(dict *ordereddict.Dict, path string, record int64) (*event.Event, int, error) {
	flat, err := winevent.Flatten(asMap(dict), r.Normaliser)
	if err != nil {
		return nil, 0, err
	}

	e := &event.Event{
		Time:     flat.Time,
		Activity: flat.Fields["EventID"],
		Origin: event.Origin{
			Path:      path,
			Record:    record,
			Producer:  producerOf(flat),
			TimeField: flat.TimeSource,
		},
		Raw: event.Fields(flat.Fields),
	}

	// A host is only recorded when the record names one. Windows writes "-" and
	// "?" where it has nothing to say, and a machine called "-" in a report is
	// worse than an admitted blank: the analyst cannot tell it from a real name.
	if !winevent.Unavailable(flat.Computer) {
		e.Host = event.Seen(flat.Computer)
		e.Add(event.KindHost, "", e.Host)
	}

	// Everything past this point — which fields become which entities, which
	// class an event belongs to — is per event identifier and comes next. The
	// reader deliberately stops at the host, so that the mapping tables are
	// written against real output rather than alongside it.
	return e, len(flat.Skipped), nil
}

// producerOf names the source of a record the way an analyst would.
//
// The channel is preferred, because "Microsoft-Windows-Sysmon/Operational" is
// what people say. But a channel is only useful when it is a name: the first
// run of this reader produced a list of sources headed by "4" with 29,475
// records, because some providers hand back a number there and the code took
// it. A number identifies nothing in a report, so it is ignored in favour of
// the provider, and if that is missing too the record is left unattributed
// rather than filed under a digit.
func producerOf(flat winevent.Flat) string {
	if flat.Channel != "" && !isAllDigits(flat.Channel) {
		return flat.Channel
	}
	return flat.Producer
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// asMap converts what the parser returns into plain Go maps.
//
// It is a copy, and copies cost. The alternative is to teach every package
// below about the parser's own types, which would put a third-party dependency
// in the one place that was deliberately kept free of it.
func asMap(d *ordereddict.Dict) map[string]any {
	out := make(map[string]any, d.Len())
	for _, k := range d.Keys() {
		v, _ := d.Get(k)
		out[k] = asAny(v)
	}
	return out
}

func asAny(v any) any {
	switch val := v.(type) {
	case *ordereddict.Dict:
		return asMap(val)
	case []any:
		list := make([]any, len(val))
		for i, item := range val {
			list[i] = asAny(item)
		}
		return list
	default:
		return v
	}
}

// Gaps reports the fields that arrived in a shape nobody declared, for the
// warning that belongs in the report.
func (r *Reader) Gaps() []normalise.Gap { return r.Normaliser.Gaps() }
