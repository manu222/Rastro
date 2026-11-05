// Package zeek reads the logs Zeek writes.
//
// It reads Zeek's output rather than packet captures, and that is a decision
// with a reason rather than a shortcut. This project's README says it does not
// reimplement the tools that already work, and reading a pcap means writing a
// protocol analyser: TCP reassembly, DNS, HTTP, the server name out of a TLS
// handshake. Zeek does all of that, every network team already runs it, and
// what is actually missing from the world is not another protocol analyser —
// it is something that ties the DNS lookup at 14:02 to the process creation at
// 14:03.
//
// The format is unusually honest and worth saying so, because most of this
// project is spent working around formats that are not. A Zeek log declares
// its own separator, the string it uses for a field that is empty, and the
// string it uses for a field that is unset — and those two are different
// things, which is a distinction Windows does not make and which this reader
// gets for free:
//
//	#separator \x09
//	#set_separator	,
//	#empty_field	(empty)
//	#unset_field	-
//	#path	dns
//	#fields	ts	uid	id.orig_h	id.orig_p	...	query	qtype_name	...
//	#types	time	string	addr	port	...	string	string	...
//
// Field names are kept exactly as Zeek writes them, dots and capitals
// included: a rule says `id.resp_p` and `Z`, and renaming either to something
// tidier would mean every rule written for Zeek stops matching.
package zeek

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/manu222/rastro/internal/event"
)

// Limits bound what one file is allowed to cost.
type Limits struct {
	MaxRecords int
	MaxBytes   int64
	MaxLine    int
}

// DefaultLimits are generous for real evidence. A conn.log of a busy day is
// large and ordinary, which is why the record limit is high.
func DefaultLimits() Limits {
	return Limits{MaxRecords: 50_000_000, MaxBytes: 16 << 30, MaxLine: 1 << 20}
}

// Stats is what the reader can say about a file afterwards.
type Stats struct {
	Records int
	// Unparsed counts lines that are not records of this log.
	Unparsed int
	// Malformed counts data lines with a different number of columns than the
	// header declares. They are skipped: a row that does not line up with its
	// header is a row whose values would be attributed to the wrong names,
	// which is worse than not reading it.
	Malformed    int
	FirstFailure error
	Stopped      string
	// Path is what the log says it is — dns, conn, http — which is also the
	// service a rule names in its logsource.
	Path string
}

// Reader walks one evidence directory's worth of Zeek logs.
type Reader struct {
	Limits Limits
	Root   string
}

// New returns a reader with the default limits.
func New(root string) *Reader { return &Reader{Limits: DefaultLimits(), Root: root} }

// header is what a TSV log declares about itself.
type header struct {
	separator    string
	setSeparator string
	emptyField   string
	unsetField   string
	path         string
	fields       []string
	types        []string
}

func defaultHeader() header {
	return header{
		separator:    "\t",
		setSeparator: ",",
		emptyField:   "(empty)",
		unsetField:   "-",
	}
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

	// The file's own name is the fallback for what kind of log this is. A log
	// named dns.log with no #path directive — which is what the JSON writer
	// produces — is still a dns log, and a rule asking for service: dns has to
	// find it. It is kept outside the header because a header can be replaced
	// mid-file and the file's name cannot.
	fallback := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".log"), ".json")
	h := defaultHeader()

	line := int64(0)
	for scan.Scan() {
		line++
		text := scan.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		if r.Limits.MaxRecords > 0 && stats.Records >= r.Limits.MaxRecords {
			stats.Stopped = fmt.Sprintf("record limit of %d reached", r.Limits.MaxRecords)
			stats.Path = h.pathOr(fallback)
			return stats, nil
		}

		// A directive. Several header blocks can appear in one file when logs
		// have been rotated and concatenated, so a second #separator resets
		// everything rather than being ignored.
		if strings.HasPrefix(text, "#") {
			if strings.HasPrefix(text, "#separator") {
				h = defaultHeader()
			}
			h.readDirective(text)
			continue
		}
		logPath := h.path
		if logPath == "" {
			logPath = fallback
		}

		var fields map[string]string
		var err error
		if strings.HasPrefix(strings.TrimSpace(text), "{") {
			fields, err = parseJSON(text, h.setSeparator)
		} else {
			fields, err = h.parseRow(text)
		}
		switch {
		case err != nil:
			stats.Unparsed++
			if stats.FirstFailure == nil {
				stats.FirstFailure = fmt.Errorf("line %d: %w", line, err)
			}
			continue
		case fields == nil:
			stats.Malformed++
			if stats.FirstFailure == nil {
				stats.FirstFailure = fmt.Errorf("line %d: the row has a different number of columns than the header declares", line)
			}
			continue
		}

		stats.Records++
		if err := emit(buildEvent(fields, logPath, rel, line)); err != nil {
			return stats, err
		}
	}
	if err := scan.Err(); err != nil {
		return stats, fmt.Errorf("%s: %w", rel, err)
	}
	stats.Path = h.pathOr(fallback)
	return stats, nil
}

// pathOr is what the log says it is, or what its file is called.
func (h header) pathOr(fallback string) string {
	if h.path != "" {
		return h.path
	}
	return fallback
}

// readDirective reads one of the lines a Zeek log opens with.
func (h *header) readDirective(text string) {
	// The separator directive is the only one that cannot be split by the
	// separator, because it is what defines it. Zeek writes it escaped.
	if rest, ok := strings.CutPrefix(text, "#separator "); ok {
		h.separator = unescapeSeparator(strings.TrimSpace(rest))
		return
	}
	parts := strings.Split(text, h.separator)
	if len(parts) < 2 {
		return
	}
	value := parts[1]
	switch parts[0] {
	case "#set_separator":
		h.setSeparator = value
	case "#empty_field":
		h.emptyField = value
	case "#unset_field":
		h.unsetField = value
	case "#path":
		h.path = value
	case "#fields":
		h.fields = append([]string(nil), parts[1:]...)
	case "#types":
		h.types = append([]string(nil), parts[1:]...)
	}
}

// unescapeSeparator reads the form Zeek writes the separator in: \x09.
func unescapeSeparator(s string) string {
	if strings.HasPrefix(s, `\x`) && len(s) == 4 {
		if n, err := strconv.ParseUint(s[2:], 16, 8); err == nil {
			return string(rune(n))
		}
	}
	if s == `\t` {
		return "\t"
	}
	return s
}

// parseRow turns one data line into named fields. It returns nil when the row
// does not line up with the header, because attributing values to the wrong
// names is worse than not reading them.
func (h *header) parseRow(text string) (map[string]string, error) {
	if len(h.fields) == 0 {
		return nil, fmt.Errorf("a data line before any #fields directive")
	}
	cols := strings.Split(text, h.separator)
	if len(cols) != len(h.fields) {
		return nil, nil
	}

	out := make(map[string]string, len(cols))
	for i, name := range h.fields {
		v := cols[i]
		switch v {
		case h.unsetField:
			// Unset means the log is saying this field has no value here. It
			// is left out of the record entirely, which is what lets a rule
			// ask whether a field is absent and get a true answer — the same
			// rule the Windows flattener follows for a field a provider did
			// not write.
			continue
		case h.emptyField:
			// Empty is not unset: the field is there and holds nothing. Zeek
			// goes to the trouble of distinguishing them, and throwing that
			// away here would be discarding something the format bothered to
			// record.
			out[name] = ""
		default:
			out[name] = v
		}
	}
	return out, nil
}

// parseJSON reads the other form Zeek writes.
//
// The two have to produce the same fields with the same text, or a rule would
// match one and not the other depending on how the network team configured
// their logging. Numbers are read as the digits they were written with rather
// than through a float64, and a list is joined with the same separator the TSV
// form uses.
func parseJSON(text, setSeparator string) (map[string]string, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("not a JSON record: %w", err)
	}
	out := make(map[string]string, len(raw))
	for name, v := range raw {
		switch val := v.(type) {
		case nil:
			// Null is the JSON form's unset, and it is left out for the same
			// reason.
			continue
		case string:
			out[name] = val
		case bool:
			// The TSV form writes T and F, so the JSON form has to as well.
			if val {
				out[name] = "T"
			} else {
				out[name] = "F"
			}
		case json.Number:
			out[name] = val.String()
		case []any:
			parts := make([]string, 0, len(val))
			for _, item := range val {
				parts = append(parts, scalarText(item))
			}
			out[name] = strings.Join(parts, setSeparator)
		default:
			out[name] = scalarText(val)
		}
	}
	return out, nil
}

func scalarText(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case json.Number:
		return val.String()
	case bool:
		if val {
			return "T"
		}
		return "F"
	default:
		return fmt.Sprint(val)
	}
}

// parseTime reads a Zeek timestamp.
//
// It is seconds since the epoch with microseconds, and it is read as two
// integers rather than through a float64 for the reason this project keeps
// relearning: 1521911720.865716 through a float64 does not come back as
// itself, and a timestamp that is a microsecond out is a timestamp that can
// reorder two events.
func parseTime(s string) (time.Time, bool) {
	whole, frac := s, ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		whole, frac = s[:dot], s[dot+1:]
	}
	secs, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if len(frac) > 9 {
		frac = frac[:9]
	}
	for len(frac) < 9 && frac != "" {
		frac += "0"
	}
	var nanos int64
	if frac != "" {
		if nanos, err = strconv.ParseInt(frac, 10, 64); err != nil {
			return time.Time{}, false
		}
	}
	return time.Unix(secs, nanos).UTC(), true
}

// buildEvent turns one row into an event.
func buildEvent(fields map[string]string, logPath, file string, line int64) *event.Event {
	e := &event.Event{
		Raw: event.Fields(fields),
		Origin: event.Origin{
			Path:      file,
			Record:    line,
			Producer:  "zeek/" + logPath,
			TimeField: "ts",
			Product:   "zeek",
			// The log's own name is the service a rule asks for: a rule
			// written for dns.log says service: dns.
			Service: logPath,
		},
	}
	if t, ok := parseTime(fields["ts"]); ok {
		e.Time = t
	}

	// No host. A Zeek log names addresses and not machines, and turning one
	// into the other needs a resolution this tool does not have. The addresses
	// are entities in their own right, which is what a report groups by until
	// something can name them.
	e.Add(event.KindAddress, "source", seen(fields["id.orig_h"]))
	e.Add(event.KindAddress, "destination", seen(fields["id.resp_h"]))

	classify(fields, logPath, e)
	return e
}

// nameOrAddress decides which of the two a value is by trying to read it as an
// address, which is the only reliable test: a name can look like anything and
// an address cannot.
func nameOrAddress(v string) event.Kind {
	if _, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		return event.KindAddress
	}
	return event.KindDomain
}

func seen(v string) event.Field {
	if v == "" {
		return event.Field{}
	}
	return event.Seen(v)
}

// classify says what a log is about.
//
// The table covers the logs the public Zeek rules are written against. A log
// that is not here keeps its fields and gets no class, which is the honest
// answer: it was read and nothing is claimed about what it was.
func classify(fields map[string]string, logPath string, e *event.Event) {
	switch logPath {
	case "conn":
		e.Class = event.ClassNetwork
		e.Action = "connection"
		e.Activity = fields["service"]

	case "dns":
		e.Class = event.ClassNetwork
		e.Action = "dns query"
		e.Activity = fields["qtype_name"]
		e.Add(event.KindDomain, "queried", seen(fields["query"]))

	case "http":
		e.Class = event.ClassNetwork
		e.Action = "http request"
		e.Activity = fields["method"]
		// The Host header is a name most of the time and an address the rest
		// of it, and which one it is decides what the report should call it.
		// Listing 10.47.3.200 under domains would be wrong in a section
		// somebody reads to decide what to block.
		e.Add(nameOrAddress(fields["host"]), "requested", seen(fields["host"]))

	case "ssl":
		e.Class = event.ClassNetwork
		e.Action = "tls handshake"
		e.Activity = fields["version"]
		// The server name is what the client asked for, which survives
		// encryption and is often the only name in the whole exchange.
		e.Add(nameOrAddress(fields["server_name"]), "requested", seen(fields["server_name"]))

	case "files":
		e.Class = event.ClassFile
		e.Action = "file seen on the wire"
		e.Activity = fields["mime_type"]
		e.Add(event.KindFile, "name", seen(fields["filename"]))
		for _, key := range []string{"md5", "sha1", "sha256"} {
			if v := fields[key]; v != "" {
				e.Add(event.KindHash, "file", event.Seen(strings.ToUpper(key)+"="+v))
			}
		}

	case "smb_files":
		e.Class = event.ClassFile
		e.Action = "file over SMB"
		e.Activity = fields["action"]
		e.Add(event.KindFile, "name", seen(fields["name"]))

	case "dce_rpc":
		e.Class = event.ClassNetwork
		e.Action = "remote procedure call"
		e.Activity = fields["operation"]

	case "notice":
		// Zeek's own finding. It is not a detection of this tool's and is not
		// presented as one, but an analyst wants to see it beside the others.
		e.Class = event.ClassLog
		e.Action = "notice raised by Zeek"
		e.Activity = fields["note"]

	case "weird":
		e.Class = event.ClassLog
		e.Action = "protocol anomaly"
		e.Activity = fields["name"]
	}
}
