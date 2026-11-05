package sigma

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Options is what a deployment knows that a rule cannot.
//
// Placeholders fills in the %name% values of rules written against a specific
// environment: which machines are domain controllers, which addresses are
// expected. An empty table is not an error — it means the rules that need one
// are refused by name, with the placeholder they wanted, so that configuring
// it is a decision somebody can make rather than a silence.
type Options struct {
	Placeholders map[string][]string
}

// Compiled is a rule ready to be run: every modifier resolved, every regular
// expression already compiled, every name in the condition checked against a
// selection that exists.
type Compiled struct {
	Rule      *Rule
	Condition Expr
	// Selections are the rule's named blocks, compiled. A selection is a
	// disjunction of field sets, because Sigma writes a list of maps to mean
	// "any of these shapes".
	Selections map[string]Selection
}

// Selection is "any of these field sets". A plain map is a selection of one.
type Selection []FieldSet

// FieldSet is "all of these field tests", which is what one map of a selection
// means.
type FieldSet []FieldTest

// FieldTest is one line of a rule: a field, and what has to be true of it.
type FieldTest struct {
	// Field is the native field name. An empty name means the test applies to
	// every field of the record, which is how a keyword search is carried.
	Field string
	// Values are the alternatives. Any one of them satisfies the test, unless
	// All is set, in which case every one of them has to.
	Values []Matcher
	All    bool
	// Null means the test is satisfied only when the field is absent. It is
	// separate from Values because it is a question about the record and not
	// about a value: the flattener does not write a field the provider did not
	// write, so absence is something this can actually ask about.
	Null bool
	// Ref names another field to compare against, for the fieldref modifier.
	Ref string
}

// Applies reports whether a rule was written for this kind of evidence.
//
// Sigma's logsource has three parts and a rule may state any of them or none.
// An unstated part matches anything, which is the specification's own rule and
// also the only safe reading: a rule that says only "product: windows" is
// making a claim about the platform and none about the channel.
//
// A rule that states nothing at all applies everywhere. That is deliberate and
// it is what keeps the rules of this repository working: they identify their
// evidence inside the detection, which is more explicit than a logsource and
// cannot be undone by a reader labelling a record differently.
//
// The other direction is strict: an event with no product does not match a
// rule that asks for one. The lenient reading is tempting — it would mean a
// reader that forgot to label its evidence still worked — and it is exactly
// the wrong trade. A reader that forgets would then run every rule against
// evidence none of them were written for, quietly. Strict turns the same
// mistake into no findings at all, which is loud, and the audit asserts that
// every reader labels what it produces so the mistake is caught in CI rather
// than in a case.
//
// The comparison is case-insensitive because the vocabulary is written by hand
// in thousands of rules and "Windows" and "windows" are the same platform.
func (c *Compiled) Applies(product, service, category string) bool {
	ls := c.Rule.Logsource
	return matchesPart(ls.Product, product) &&
		matchesPart(ls.Service, service) &&
		matchesPart(ls.Category, category)
}

func matchesPart(want, have string) bool {
	if want == "" {
		return true
	}
	return strings.EqualFold(want, have)
}

// Result is what a directory of rules came to.
type Result struct {
	Rules []*Compiled
	// Refused is every rule that was not loaded, with the reason. This is the
	// list that has to reach the report: a rule that was refused is coverage
	// the analysis does not have.
	Refused []*Unsupported
}

// ByFeature counts refusals by what was not supported, so that the next thing
// worth implementing is decided by a number.
func (r Result) ByFeature() map[string]int {
	out := map[string]int{}
	for _, u := range r.Refused {
		out[u.Feature]++
	}
	return out
}

// LoadDir reads every .yml and .yaml file under root.
//
// It does not stop at the first rule it cannot handle. A directory of rules is
// evidence about what the rule author wrote, not a program to be compiled, and
// the useful answer is "these loaded, those did not, here is why" rather than
// an error about whichever file came first alphabetically.
func LoadDir(root string) (Result, error) { return LoadDirWith(root, Options{}) }

// LoadDirWith is LoadDir with the deployment's own knowledge supplied.
func LoadDirWith(root string, opt Options) (Result, error) {
	var res Result
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yml", ".yaml":
		default:
			return nil
		}
		c, uerr := LoadFileWith(path, opt)
		switch {
		case uerr == nil:
			res.Rules = append(res.Rules, c)
		default:
			var u *Unsupported
			if ok := asUnsupported(uerr, &u); ok {
				res.Refused = append(res.Refused, u)
				return nil
			}
			return uerr
		}
		return nil
	})
	return res, err
}

func asUnsupported(err error, out **Unsupported) bool {
	if u, ok := err.(*Unsupported); ok {
		*out = u
		return true
	}
	return false
}

// LoadFile reads and compiles one rule. Every failure that is a property of the
// rule rather than of the disk comes back as *Unsupported, carrying the title
// and the reason.
func LoadFile(path string) (*Compiled, error) { return LoadFileWith(path, Options{}) }

// LoadFileWith is LoadFile with the deployment's own knowledge supplied.
func LoadFileWith(path string, opt Options) (*Compiled, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rule Rule
	if err := yaml.Unmarshal(raw, &rule); err != nil {
		return nil, &Unsupported{Path: path, Reason: fmt.Sprintf("not readable as YAML: %v", err), Feature: FeatureStructure}
	}
	rule.Path = path

	// A file with no detection block is not a rule. SigmaHQ ships a few:
	// deprecated stubs, and the documentation of the format itself.
	if rule.Title == "" && rule.Detection == nil {
		return nil, &Unsupported{Path: path, Reason: "no title and no detection block", Feature: FeatureStructure}
	}

	refuse := func(feature, format string, args ...any) *Unsupported {
		return &Unsupported{
			Path:    path,
			Title:   rule.Title,
			Reason:  fmt.Sprintf(format, args...),
			Feature: feature,
		}
	}

	if rule.Correlation != nil {
		return nil, refuse(FeatureCorrelation,
			"describes a correlation between rules, which this engine does not evaluate")
	}
	if rule.Detection == nil {
		return nil, refuse(FeatureStructure, "no detection block")
	}

	condText, err := conditionText(rule.Detection["condition"])
	if err != nil {
		return nil, refuse(FeatureCondition, "%v", err)
	}
	switch {
	case strings.Contains(condText, "|"):
		return nil, refuse(FeatureAggregation,
			"the condition aggregates (%s), which needs a time window this engine does not keep", condText)
	case strings.Contains(" "+strings.ToLower(condText)+" ", " near "):
		return nil, refuse(FeatureNear,
			"the condition uses near, which needs a time window this engine does not keep")
	}

	c := &Compiled{Rule: &rule, Selections: map[string]Selection{}}
	known := map[string]bool{}
	for name, block := range rule.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		sel, err := compileSelection(block, opt)
		if err != nil {
			feature := FeatureModifier
			switch {
			case strings.Contains(err.Error(), "regular expression"):
				feature = FeatureRegexp
			case strings.Contains(err.Error(), "placeholder"):
				feature = FeaturePlaceholder
			case strings.Contains(err.Error(), "shape"):
				feature = FeatureStructure
			}
			return nil, refuse(feature, "selection %s: %v", name, err)
		}
		c.Selections[name] = sel
		known[name] = true
	}
	if len(known) == 0 {
		return nil, refuse(FeatureStructure, "the detection block has a condition and nothing to select")
	}

	expr, err := parseCondition(condText, known)
	if err != nil {
		return nil, refuse(FeatureCondition, "condition %q: %v", condText, err)
	}
	c.Condition = expr
	return c, nil
}

// conditionText accepts the two shapes a condition can arrive in. A list of
// conditions means the rule fires on any of them, which is an or.
func conditionText(v any) (string, error) {
	switch cond := v.(type) {
	case nil:
		return "", fmt.Errorf("no condition")
	case string:
		if strings.TrimSpace(cond) == "" {
			return "", fmt.Errorf("empty condition")
		}
		return cond, nil
	case []any:
		parts := make([]string, 0, len(cond))
		for _, item := range cond {
			s, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("a condition in the list is not text")
			}
			parts = append(parts, "("+s+")")
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("empty condition list")
		}
		return strings.Join(parts, " or "), nil
	default:
		return "", fmt.Errorf("condition is %T, not text", v)
	}
}

// compileSelection handles the shapes a selection can take: a map of field
// tests, a list of such maps, or — for a selection that tests the whole event
// rather than a named field — a list of plain values.
func compileSelection(block any, opt Options) (Selection, error) {
	switch b := block.(type) {
	case map[string]any:
		set, err := compileFieldSet(b, opt)
		if err != nil {
			return nil, err
		}
		return Selection{set}, nil

	case []any:
		var sel Selection
		for _, item := range b {
			switch inner := item.(type) {
			case map[string]any:
				set, err := compileFieldSet(inner, opt)
				if err != nil {
					return nil, err
				}
				sel = append(sel, set)
			case nil:
				return nil, fmt.Errorf("unsupported shape: a null in a list of selections")
			default:
				// Sigma's keyword form: a list of plain values that the rule
				// expects to be looked for in the record rather than in a
				// named field. A list of keywords matches when any one of them
				// does, so each becomes a field set of its own.
				set, err := compileKeyword(inner, nil, opt)
				if err != nil {
					return nil, err
				}
				sel = append(sel, set)
			}
		}
		if len(sel) == 0 {
			return nil, fmt.Errorf("unsupported shape: empty selection")
		}
		return sel, nil

	case string, int, int64, uint64, float64, bool:
		set, err := compileKeyword(b, nil, opt)
		if err != nil {
			return nil, err
		}
		return Selection{set}, nil

	default:
		return nil, fmt.Errorf("unsupported shape: selection is %T", block)
	}
}

// compileKeyword builds the test for one keyword.
//
// What "the record" means has to be decided somewhere, and it is decided here
// and written down: a keyword is looked for in the value of every field of the
// flattened event. The alternative definitions are worse. Searching a rendered
// message is impossible, because this tool never renders one — it reads the
// fields a provider wrote, not the sentence Windows would have built out of
// them. Searching a chosen subset of fields would be an engine deciding what a
// rule meant.
//
// A plain keyword is a substring test, which is what the backends Sigma was
// written for do with one: a rule saying "Sudo Command Not Found" is looking
// for that text inside a message and not for a field whose whole value is it.
// A keyword that carries its own wildcards keeps them.
func compileKeyword(v any, mods []string, opt Options) (FieldSet, error) {
	text, err := scalarText(v)
	if err != nil {
		return nil, err
	}
	if _, hasWildcard := unescape(text); !hasWildcard && len(mods) == 0 {
		mods = []string{"contains"}
	}
	m, err := compileValue(text, mods, opt)
	if err != nil {
		return nil, err
	}
	// The empty field name is what says "any field". Nothing else in a rule can
	// produce it, because a Sigma field name is never empty.
	return FieldSet{{Field: "", Values: []Matcher{m}}}, nil
}

func compileFieldSet(m map[string]any, opt Options) (FieldSet, error) {
	set := make(FieldSet, 0, len(m))
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	// Stable order so that a rule reads the same way every time it is loaded.
	sortStrings(names)

	for _, key := range names {
		field, mods := splitModifiers(key)
		test := FieldTest{Field: field}

		for _, mod := range mods {
			if mod == "all" {
				test.All = true
			}
			if mod == "fieldref" {
				test.Ref = "pending"
			}
		}

		switch v := m[key].(type) {
		case nil:
			// `field: null` asks whether the provider wrote the field at all.
			test.Null = true

		case []any:
			for _, item := range v {
				if item == nil {
					// A null inside a list is "absent or one of these", which
					// Sigma allows and which this keeps as a separate test on
					// the same field.
					test.Null = true
					continue
				}
				m, err := compileOne(item, mods, &test, opt)
				if err != nil {
					return nil, err
				}
				if m != nil {
					test.Values = append(test.Values, m)
				}
			}

		default:
			m, err := compileOne(v, mods, &test, opt)
			if err != nil {
				return nil, err
			}
			if m != nil {
				test.Values = append(test.Values, m)
			}
		}

		if len(test.Values) == 0 && !test.Null && test.Ref == "" {
			return nil, fmt.Errorf("field %s has nothing to match against", field)
		}
		set = append(set, test)
	}
	return set, nil
}

// compileOne turns one scalar out of the YAML into a matcher. A fieldref value
// is not a matcher at all: it names another field, so it is recorded on the
// test instead.
func compileOne(v any, mods []string, test *FieldTest, opt Options) (Matcher, error) {
	text, err := scalarText(v)
	if err != nil {
		return nil, err
	}
	if test.Ref != "" {
		test.Ref = text
		return nil, nil
	}
	return compileValue(text, mods, opt)
}

// scalarText renders whatever YAML produced as the text a rule means. Numbers
// and booleans are compared as the text the provider writes, because the flat
// view of an event is text: Sigma's `EventID: 1` has to match the field "1".
func scalarText(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case int:
		return fmt.Sprintf("%d", val), nil
	case int64:
		return fmt.Sprintf("%d", val), nil
	case uint64:
		return fmt.Sprintf("%d", val), nil
	case float64:
		// YAML gives a float for any number with a decimal point. Printed
		// without an exponent so that a rule written as 1.5 matches "1.5".
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", val), "0"), "."), nil
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	default:
		return "", fmt.Errorf("unsupported shape: value is %T", v)
	}
}

// splitModifiers takes "CommandLine|base64offset|contains" apart.
func splitModifiers(key string) (field string, mods []string) {
	parts := strings.Split(key, "|")
	return parts[0], parts[1:]
}
