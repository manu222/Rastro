package report

import (
	"encoding/json"
	"io"
)

// JSON writes the whole report as data.
//
// It takes no section argument, and that is a decision rather than an
// oversight. The sections are a presentation choice — which of the three
// questions a reader wants answered first — and a consumer of this output is
// not a reader. A SIEM, a notebook or the next tool in a pipeline wants every
// field and will pick what it needs, and a feed that silently omits the
// timeline because somebody passed a flag is a feed that cannot be relied on.
//
// The shape is the same structure the other two renderings walk, so a field
// that appears in the Markdown appears here under a name a machine can read.
// Indented on purpose: these files end up in tickets and in version control,
// and a one-line JSON blob diffs as one changed line however much of it
// changed.
func JSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Evidence can contain anything, including values that happen to look like
	// HTML. Escaping is left on so that a report embedded in a web page by
	// something downstream cannot carry a script out of the logs it describes.
	enc.SetEscapeHTML(true)
	return enc.Encode(r)
}
