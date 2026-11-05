package sigma

import (
	"fmt"
	"strings"
)

// The condition of a Sigma rule is a small boolean language over the names of
// its own selections:
//
//	selection and not 1 of filter_main_*
//	process_creation and ((a and b) or c)
//	all of selection_* and not them
//
// It is parsed into a tree rather than interpreted from the text on every
// event, and — more importantly — every name it mentions is checked against the
// selections the rule actually defines. A condition that refers to
// `filter_mian` because somebody typed it wrong is a rule that silently stops
// filtering, and that is exactly the class of mistake this package refuses to
// pass on.

// Expr is a node of a parsed condition.
type Expr interface {
	// Names lists every selection the expression refers to, so that the loader
	// can check them before the rule is ever run.
	Names() []string
	String() string
}

// Ref is a reference to one named selection.
type Ref struct{ Name string }

func (e Ref) Names() []string { return []string{e.Name} }
func (e Ref) String() string  { return e.Name }

// And, Or and Not are the operators.
type And struct{ Left, Right Expr }

func (e And) Names() []string { return append(e.Left.Names(), e.Right.Names()...) }
func (e And) String() string  { return "(" + e.Left.String() + " and " + e.Right.String() + ")" }

type Or struct{ Left, Right Expr }

func (e Or) Names() []string { return append(e.Left.Names(), e.Right.Names()...) }
func (e Or) String() string  { return "(" + e.Left.String() + " or " + e.Right.String() + ")" }

type Not struct{ Inner Expr }

func (e Not) Names() []string { return e.Inner.Names() }
func (e Not) String() string  { return "not " + e.Inner.String() }

// Quantifier is "1 of selection_*" or "all of them": a group of selections
// joined by or, or by and.
//
// The group is resolved when the rule is loaded, not when it runs. Resolving it
// later would mean a pattern that matches nothing — because the prefix is
// misspelled — turns into an expression over an empty set, and an empty "1 of"
// is false while an empty "all of" is true. Both are wrong answers that look
// like results.
type Quantifier struct {
	All     bool // all of ... rather than 1 of ...
	Pattern string
	Matched []string
}

func (e Quantifier) Names() []string { return e.Matched }
func (e Quantifier) String() string {
	which := "1 of"
	if e.All {
		which = "all of"
	}
	return which + " " + e.Pattern
}

// parseCondition builds the tree. known is the set of selection names the rule
// defines, used to resolve quantifier patterns and to reject names that are
// not there.
func parseCondition(text string, known map[string]bool) (Expr, error) {
	p := &condParser{tokens: tokenizeCondition(text), known: known}
	e, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected %q", p.tokens[p.pos])
	}
	return e, nil
}

type condParser struct {
	tokens []string
	pos    int
	known  map[string]bool
}

// tokenizeCondition splits on whitespace and parentheses. Sigma identifiers are
// letters, digits and underscores, with a trailing star in a quantifier
// pattern, so nothing else needs lexing.
func tokenizeCondition(text string) []string {
	// A condition written as a YAML block scalar arrives with newlines in it.
	text = strings.Join(strings.Fields(text), " ")
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case ' ':
			flush()
		case '(', ')':
			flush()
			out = append(out, string(c))
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func (p *condParser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *condParser) take() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.take()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = Or{Left: left, Right: right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.take()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = And{Left: left, Right: right}
	}
	return left, nil
}

func (p *condParser) parseNot() (Expr, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.take()
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return Not{Inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (Expr, error) {
	switch t := p.peek(); {
	case t == "":
		return nil, fmt.Errorf("condition ends where a selection was expected")

	case t == "(":
		p.take()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.take() != ")" {
			return nil, fmt.Errorf("unclosed parenthesis")
		}
		return inner, nil

	case strings.EqualFold(t, "1"), strings.EqualFold(t, "any"), strings.EqualFold(t, "all"):
		return p.parseQuantifier()

	case strings.EqualFold(t, "and"), strings.EqualFold(t, "or"), strings.EqualFold(t, "not"), t == ")":
		return nil, fmt.Errorf("unexpected %q", t)
	}

	name := p.take()
	if !p.known[name] {
		// The typo case. A name that is not defined cannot be matched against
		// anything, so the rule is refused rather than loaded with a hole in
		// it.
		return nil, fmt.Errorf("condition refers to %q, which the rule does not define", name)
	}
	return Ref{Name: name}, nil
}

func (p *condParser) parseQuantifier() (Expr, error) {
	which := p.take()
	all := strings.EqualFold(which, "all")

	if !strings.EqualFold(p.peek(), "of") {
		// "1" on its own is not a selection name, and neither is "all".
		return nil, fmt.Errorf("expected \"of\" after %q", which)
	}
	p.take()

	pattern := p.take()
	if pattern == "" {
		return nil, fmt.Errorf("expected a selection pattern after %q of", which)
	}

	var matched []string
	if strings.EqualFold(pattern, "them") {
		for name := range p.known {
			matched = append(matched, name)
		}
	} else {
		for name := range p.known {
			if matchesPrefixPattern(name, pattern) {
				matched = append(matched, name)
			}
		}
	}
	if len(matched) == 0 {
		// An empty group is the dangerous case: "1 of nothing" is false and
		// "all of nothing" is true, so a misspelled prefix would quietly turn
		// a filter on or off.
		return nil, fmt.Errorf("%s of %s matches none of the rule's selections", which, pattern)
	}
	sortStrings(matched)
	return Quantifier{All: all, Pattern: pattern, Matched: matched}, nil
}

// matchesPrefixPattern handles the one wildcard shape a quantifier can use.
func matchesPrefixPattern(name, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return name == pattern
	}
	return globMatch(strings.ToLower(name), strings.ToLower(pattern))
}

// sortStrings keeps the resolved group in a stable order so that a rule's
// String() and any output built from it do not change between runs.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
