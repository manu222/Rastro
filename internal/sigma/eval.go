package sigma

import "strings"

// Running a rule is deliberately dull. Every decision was made when the rule
// was loaded — which modifier means what, whether a regular expression
// compiles, whether the condition names anything that does not exist — so what
// is left here is walking a tree and comparing strings.
//
// That is the point of the split. This code runs once per rule per event, which
// over a real case is tens of millions of times, and the way to make that
// bearable is not to be clever here but to have left nothing to decide.

// Matches reports whether the rule matches one event.
//
// fields is the flat view of the record: the source's own field names, with the
// values the provider wrote. A field that is not in the map was not in the
// record, which is what makes a rule asking for null answerable.
func (c *Compiled) Matches(fields map[string]string) bool {
	return c.eval(c.Condition, fields)
}

func (c *Compiled) eval(e Expr, fields map[string]string) bool {
	switch node := e.(type) {
	case Ref:
		return c.Selections[node.Name].matches(fields)
	case And:
		return c.eval(node.Left, fields) && c.eval(node.Right, fields)
	case Or:
		return c.eval(node.Left, fields) || c.eval(node.Right, fields)
	case Not:
		return !c.eval(node.Inner, fields)
	case Quantifier:
		if node.All {
			for _, name := range node.Matched {
				if !c.Selections[name].matches(fields) {
					return false
				}
			}
			return true
		}
		for _, name := range node.Matched {
			if c.Selections[name].matches(fields) {
				return true
			}
		}
		return false
	default:
		// Unreachable: the loader builds the tree and refuses anything it
		// cannot build. Returning false rather than panicking means a bug here
		// costs a missed detection and not a crashed analysis, and the missed
		// detection shows up in the equivalence test against the reference
		// engine.
		return false
	}
}

// matches is "any of these shapes", which is what a list of maps under one
// selection name means.
func (s Selection) matches(fields map[string]string) bool {
	for _, set := range s {
		if set.matches(fields) {
			return true
		}
	}
	return false
}

// matches is "all of these field tests", which is what one map means.
func (f FieldSet) matches(fields map[string]string) bool {
	for i := range f {
		if !f[i].matches(fields) {
			return false
		}
	}
	return true
}

func (t FieldTest) matches(fields map[string]string) bool {
	// A keyword is not bound to a field: it is looked for in every value the
	// record has.
	if t.Field == "" {
		for _, v := range fields {
			if t.anyValue(v) {
				return true
			}
		}
		return false
	}

	value, present := fields[t.Field]

	// fieldref compares two fields of the same record against each other.
	// Absent on either side is not equality: a record that mentions neither is
	// not a record where they are the same.
	if t.Ref != "" {
		other, otherPresent := fields[t.Ref]
		if !present || !otherPresent {
			return false
		}
		return strings.EqualFold(value, other)
	}

	if !present {
		// The field was never written. Only a rule that asked about absence is
		// satisfied by that.
		return t.Null
	}
	if t.Null && len(t.Values) == 0 {
		// The rule asked for the field to be absent and it is here.
		return false
	}

	if t.All {
		for _, m := range t.Values {
			if !m.Match(value) {
				return false
			}
		}
		return len(t.Values) > 0
	}
	return t.anyValue(value)
}

func (t FieldTest) anyValue(value string) bool {
	for _, m := range t.Values {
		if m.Match(value) {
			return true
		}
	}
	return false
}

// Hit is one reason a rule fired: a field of the record, the value that was in
// it, and the pattern out of the rule that it satisfied.
//
// This is what level two of the report is made of. "Rule 1 fired" is not an
// answer an analyst can act on; "rule 1 fired because GrantedAccess was 0x1010
// and TargetImage ended in \lsass.exe" is.
type Hit struct {
	Selection string
	Field     string
	Value     string
	Pattern   string
}

// Explain returns the hits behind a match.
//
// It is a second pass, run only on the events that matched, and that is on
// purpose. Collecting the reasons costs allocations, matches are rare — a few
// hundred out of tens of thousands — and paying for the explanation on every
// event that was never going to fire would be paying for nothing almost all of
// the time.
//
// Only the selections the match actually depended on are walked. A rule that
// fired because of `selection and not filter` has nothing to say about the
// filter: the filter did not match, and listing what it looked for would read
// like a reason when it is the opposite of one.
func (c *Compiled) Explain(fields map[string]string) []Hit {
	var hits []Hit
	c.collect(c.Condition, fields, false, &hits)
	return hits
}

// collect walks the tree the same way eval does, skipping the branches that did
// not contribute. negated tracks whether the branch sits under a not, because
// what a filter looked for is not a reason the rule fired.
func (c *Compiled) collect(e Expr, fields map[string]string, negated bool, hits *[]Hit) {
	switch node := e.(type) {
	case Ref:
		if negated {
			return
		}
		c.collectSelection(node.Name, fields, hits)
	case And:
		c.collect(node.Left, fields, negated, hits)
		c.collect(node.Right, fields, negated, hits)
	case Or:
		// Only the side that matched is a reason.
		if c.eval(node.Left, fields) {
			c.collect(node.Left, fields, negated, hits)
		}
		if c.eval(node.Right, fields) {
			c.collect(node.Right, fields, negated, hits)
		}
	case Not:
		c.collect(node.Inner, fields, !negated, hits)
	case Quantifier:
		if negated {
			return
		}
		for _, name := range node.Matched {
			if c.Selections[name].matches(fields) {
				c.collectSelection(name, fields, hits)
			}
		}
	}
}

func (c *Compiled) collectSelection(name string, fields map[string]string, hits *[]Hit) {
	for _, set := range c.Selections[name] {
		if !set.matches(fields) {
			continue
		}
		for _, test := range set {
			if test.Field == "" {
				// A keyword: name the field it was found in, which is the part
				// an analyst needs in order to go and look.
				for field, v := range fields {
					if test.anyValue(v) {
						*hits = append(*hits, Hit{
							Selection: name, Field: field, Value: v,
							Pattern: patternOf(test, v),
						})
						break
					}
				}
				continue
			}
			value := fields[test.Field]
			*hits = append(*hits, Hit{
				Selection: name, Field: test.Field, Value: value,
				Pattern: patternOf(test, value),
			})
		}
		// One matching shape is enough to explain the selection.
		return
	}
}

// patternOf names the written value that the record satisfied, so that a
// finding can quote the rule rather than paraphrase it.
func patternOf(t FieldTest, value string) string {
	if t.Ref != "" {
		return t.Ref
	}
	for _, m := range t.Values {
		if m.Match(value) {
			return m.String()
		}
	}
	if t.Null {
		return "null"
	}
	return ""
}
