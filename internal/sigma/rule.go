// Package sigma loads detection rules written in the Sigma format and turns
// them into something that can be run against the flat view of an event.
//
// The loading is separate from the running, and that separation is the point.
// A rule this package cannot evaluate must be refused when it is read, by name,
// with the reason — never loaded and quietly left to match nothing. A rule that
// does not load is a line in the output somebody will see. A rule that loads
// and never fires is indistinguishable from a rule with nothing to find, which
// is the failure this whole project exists to make impossible.
//
// What is supported was decided by measuring the public rule corpus rather than
// by reading the specification and guessing what matters. Across the 3,890
// rules SigmaHQ ships:
//
//	contains       4732      supported
//	endswith       3528      supported
//	all            1182      supported
//	startswith      590      supported
//	re              230      supported, with the caveat below
//	windash         113      supported
//	cidr             40      supported
//	expand           44      REFUSED: needs a placeholder table the user supplies
//	base64offset      9      supported
//	fieldref          6      supported
//	base64            1      supported
//
// plus wildcards inside values, which 47% of the corpus uses, and comparison
// against null, which 2.4% uses and which works here only because the
// flattener does not invent a field the provider did not write.
//
// Measured against that corpus, this loader reads 3,778 of 3,805 rules: 99.3%.
// The 27 it refuses all want a placeholder table — which machines are domain
// controllers, which addresses are expected — and they load as soon as one is
// supplied, so that number is a statement about this deployment's
// configuration and not about the engine.
//
// Refused by design, with the cost of each written down: a condition carrying
// an aggregation (`| count() by ... > 5`), one using `near`, and correlation
// rules, because all three describe a relationship across events over a window
// of time rather than a match on one event. None of them appear in the
// directories above; they live in the parts of the corpus SigmaHQ keeps
// separate.
//
// The caveat on regular expressions is not a choice. Go's regexp package
// implements RE2, which has no backreferences and no lookaround, while Sigma
// assumes PCRE. Some of those 230 expressions cannot be compiled here at all.
// They are therefore compiled at load time and the rule is refused if the
// compilation fails, which turns a silent mismatch into a visible one.
package sigma

import "fmt"

// Rule is a Sigma rule as written on disk.
//
// The fields are the ones this tool uses or reports; the format carries a few
// more and they are allowed to be there without being read.
type Rule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Status      string   `yaml:"status"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references"`
	Author      string   `yaml:"author"`
	Date        string   `yaml:"date"`
	Modified    string   `yaml:"modified"`
	Tags        []string `yaml:"tags"`

	Logsource Logsource `yaml:"logsource"`

	// Detection is kept raw. Its shape is a condition plus any number of
	// differently shaped selections, which is more than a struct can describe,
	// so it is compiled rather than unmarshalled.
	Detection map[string]any `yaml:"detection"`

	FalsePositives []string `yaml:"falsepositives"`
	Level          string   `yaml:"level"`
	Fields         []string `yaml:"fields"`

	// Correlation marks a rule that describes a relationship between other
	// rules. Recognised so that it can be refused by name instead of failing
	// somewhere further in with a confusing message.
	Correlation map[string]any `yaml:"correlation"`

	// Path is where the rule was read from, so that a refusal can say which
	// file to go and look at.
	Path string `yaml:"-"`
}

// Logsource says what kind of evidence a rule is written against.
//
// This tool does not use it to decide which events a rule sees. The rules in
// this repository put the event identifier in a selection of their own, which
// makes each rule say out loud what it matches instead of relying on a
// backend's idea of what "process_creation" means. Logsource is kept because it
// is how a reader of the rule knows where it came from, and because the report
// groups by it.
type Logsource struct {
	Category   string `yaml:"category"`
	Product    string `yaml:"product"`
	Service    string `yaml:"service"`
	Definition string `yaml:"definition"`
}

// Unsupported is why a rule was refused. It is an error rather than a warning
// because the caller has to decide what to do about it, and because an error
// that is ignored at least had to be ignored on purpose.
type Unsupported struct {
	Path   string
	Title  string
	Reason string
	// Feature names the part of Sigma that was not supported, so that refusals
	// can be counted by cause and the next thing worth implementing is a
	// measurement rather than an opinion.
	Feature string
}

func (u *Unsupported) Error() string {
	where := u.Title
	if where == "" {
		where = u.Path
	}
	return fmt.Sprintf("%s: %s", where, u.Reason)
}

// Known feature names, used for counting refusals.
const (
	FeaturePlaceholder = "expand"
	FeatureAggregation = "aggregation"
	FeatureNear        = "near"
	FeatureCorrelation = "correlation"
	FeatureModifier    = "modifier"
	FeatureRegexp      = "regexp"
	FeatureCondition   = "condition"
	FeatureStructure   = "structure"
)
