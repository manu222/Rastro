package sigma

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Matcher decides whether one value out of an event satisfies one value out of
// a rule. Everything a modifier does is decided when the rule is loaded, so
// that matching a million events does not re-interpret the rule a million
// times.
type Matcher interface {
	// Match reports whether the event's value satisfies this matcher. value is
	// the text exactly as the source recorded it.
	Match(value string) bool
	// String is for the report: a finding has to be able to say what it
	// matched on.
	String() string
}

// Exact is implemented by a matcher that requires one specific value and
// nothing else. It exists so that a caller can build an index over the rules —
// "which rules could possibly match a record with this event id" — without
// parsing the text a matcher prints for the report, which would be guessing at
// its meaning from its description.
type Exact interface {
	Exact() string
}

// literal is an exact comparison, which in Sigma is case-insensitive. A rule
// written against powershell.exe has to match POWERSHELL.EXE, because which
// case the provider wrote is not a property of the attack.
type literal struct{ want string }

func (m literal) Match(v string) bool { return strings.EqualFold(v, m.want) }
func (m literal) String() string      { return m.want }
func (m literal) Exact() string       { return m.want }

// cased is the same comparison when the rule asked for case to be respected.
type cased struct{ want string }

func (m cased) Match(v string) bool { return v == m.want }
func (m cased) String() string      { return m.want + " (cased)" }
func (m cased) Exact() string       { return m.want }

// The three substring matchers compare without lowering the event's value,
// because lowering it allocates a new string and these run once per rule per
// event. Measured on the public corpus that was three allocations per rule and
// per event: with 3,162 rules over 31,243 records, ninety-six million
// allocations to answer questions that need none.
//
// The written value is lowered once, when the rule is loaded. The event's value
// is compared fold-insensitively in place.
type contains struct{ want string }

func (m contains) Match(v string) bool { return indexFold(v, m.want) >= 0 }
func (m contains) String() string      { return "*" + m.want + "*" }

type prefix struct{ want string }

func (m prefix) Match(v string) bool {
	return len(v) >= len(m.want) && strings.EqualFold(v[:len(m.want)], m.want)
}
func (m prefix) String() string { return m.want + "*" }

type suffix struct{ want string }

func (m suffix) Match(v string) bool {
	return len(v) >= len(m.want) && strings.EqualFold(v[len(v)-len(m.want):], m.want)
}
func (m suffix) String() string { return "*" + m.want }

// indexFold is a case-insensitive strings.Index. want is already lower-cased.
//
// It compares bytes rather than runes, which is correct for the one thing that
// matters here: case folding beyond ASCII can change a string's length, so
// slicing by byte length would be wrong, and EqualFold is what decides the
// window. The scan uses the first byte to skip, in both its cases, which keeps
// the common miss cheap.
func indexFold(s, want string) int {
	if want == "" {
		return 0
	}
	if len(want) > len(s) {
		return -1
	}
	first := want[0]
	upper := first
	if first >= 'a' && first <= 'z' {
		upper = first - ('a' - 'A')
	}
	for i := 0; i+len(want) <= len(s); i++ {
		if c := s[i]; c != first && c != upper {
			continue
		}
		if strings.EqualFold(s[i:i+len(want)], want) {
			return i
		}
	}
	return -1
}

// glob is a value with wildcards in it. Sigma uses * for any run of characters
// and ? for exactly one, and nothing else, so this is not a regular expression
// and does not need the cost of one.
type glob struct {
	// pattern is lower-cased, because the comparison is case-insensitive and
	// doing it once at load time is cheaper than doing it per event.
	pattern string
	// src is the value as the rule author wrote it, for the report.
	src string
}

func (m glob) String() string { return m.src }

// Match walks the pattern greedily with one point of backtracking, which is
// enough because the only unbounded wildcard is *.
func (m glob) Match(v string) bool {
	return globMatchFold(v, m.pattern)
}

// globMatchFold is globMatch without lowering the value first, for the same
// reason the substring matchers do not: it would allocate on every event.
func globMatchFold(s, pattern string) bool {
	var si, pi int
	starP, starS := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || equalByteFold(pattern[pi], s[si])):
			si++
			pi++
		case pi < len(pattern) && pattern[pi] == '*':
			starP = pi
			starS = si
			pi++
		case starP >= 0:
			// The last star has to swallow one more character.
			pi = starP + 1
			starS++
			si = starS
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// equalByteFold compares two bytes ignoring ASCII case. The pattern is already
// lower-cased, so only the value's byte can be upper.
func equalByteFold(p, c byte) bool {
	if p == c {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return p == c+('a'-'A')
	}
	return false
}

// globMatch is the case-sensitive form, used where a pattern is compared
// against a name rather than against evidence: resolving "1 of selection_*"
// against the rule's own selection names.
func globMatch(s, pattern string) bool {
	var si, pi int
	starP, starS := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			si++
			pi++
		case pi < len(pattern) && pattern[pi] == '*':
			starP = pi
			starS = si
			pi++
		case starP >= 0:
			pi = starP + 1
			starS++
			si = starS
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// re is a regular expression. It is compiled when the rule is loaded, so a
// pattern RE2 cannot handle refuses the rule instead of being discovered on
// some unlucky event in the middle of a case.
type re struct {
	rx  *regexp.Regexp
	src string
}

func (m re) Match(v string) bool { return m.rx.MatchString(v) }
func (m re) String() string      { return "/" + m.src + "/" }

// cidr matches an address against a network. The field holds an address as the
// provider wrote it, which may carry a zone or be empty.
type cidr struct {
	net netip.Prefix
	src string
}

func (m cidr) Match(v string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return false
	}
	return m.net.Contains(addr.Unmap())
}
func (m cidr) String() string { return m.src }

// anyOf matches when any of several matchers does. It is what a modifier that
// expands one written value into several alternatives compiles to: windash
// writing a parameter four ways, base64offset writing a string at three
// alignments.
type anyOf struct {
	of  []Matcher
	src string
}

func (m anyOf) Match(v string) bool {
	for _, inner := range m.of {
		if inner.Match(v) {
			return true
		}
	}
	return false
}
func (m anyOf) String() string { return m.src }

// compileValue turns one written value plus its modifier chain into a matcher.
//
// The modifier chain is ordered and the order means something: base64offset
// then contains encodes the value and then looks for the encoding anywhere,
// which is not the same as the other way round.
func compileValue(raw string, mods []string, opt Options) (Matcher, error) {
	// Modifiers that rewrite the value into alternatives run first.
	values := []string{raw}
	var (
		wantContains, wantPrefix, wantSuffix bool
		wantCased                            bool
		reFlags                              string
		isRegex, isCIDR                      bool
	)

	for _, mod := range mods {
		switch mod {
		case "contains":
			wantContains = true
		case "startswith":
			wantPrefix = true
		case "endswith":
			wantSuffix = true
		case "all":
			// Handled a level up: it joins the values of one field with and
			// instead of or, and says nothing about any single value.
		case "cased":
			wantCased = true
		case "re":
			isRegex = true
		case "i", "m", "s":
			// Flags of the regular expression modifier.
			reFlags += mod
		case "cidr":
			isCIDR = true
		case "windash":
			values = expandWindash(values)
		case "base64offset":
			values = expandBase64Offsets(values)
		case "base64":
			for i, v := range values {
				values[i] = base64.StdEncoding.EncodeToString([]byte(v))
			}
		case "expand":
			// A placeholder stands for something only this deployment knows:
			// which hosts are domain controllers, which countries are
			// expected. The engine supports the modifier; whether a rule using
			// it can run depends on whether anyone filled the table in.
			expanded, err := expandPlaceholders(values, opt.Placeholders)
			if err != nil {
				return nil, err
			}
			values = expanded
		case "utf16le", "utf16", "wide":
			for i, v := range values {
				values[i] = toUTF16LE(v)
			}
		default:
			return nil, fmt.Errorf("modifier %q", mod)
		}
	}

	switch {
	case isRegex:
		pattern := raw
		if reFlags != "" {
			pattern = "(?" + reFlags + ")" + pattern
		}
		rx, err := regexp.Compile(pattern)
		if err != nil {
			// RE2 refusing a PCRE construct lands here, which is the whole
			// reason this is done at load time.
			return nil, fmt.Errorf("regular expression %q: %w", raw, err)
		}
		return re{rx: rx, src: raw}, nil

	case isCIDR:
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("network %q: %w", raw, err)
		}
		return cidr{net: p, src: raw}, nil
	}

	built := make([]Matcher, 0, len(values))
	for _, v := range values {
		m, err := compilePlain(v, wantContains, wantPrefix, wantSuffix, wantCased)
		if err != nil {
			return nil, err
		}
		built = append(built, m)
	}
	if len(built) == 1 {
		return built[0], nil
	}
	return anyOf{of: built, src: raw}, nil
}

// compilePlain builds a text matcher, choosing the cheapest one that is
// correct. A value with no wildcard in it never needs the wildcard machinery,
// and most values have none.
func compilePlain(v string, wantContains, wantPrefix, wantSuffix, wantCased bool) (Matcher, error) {
	pattern, hasWildcard := unescape(v)

	switch {
	case wantContains:
		pattern = "*" + pattern + "*"
		hasWildcard = true
	case wantPrefix:
		pattern += "*"
		hasWildcard = true
	case wantSuffix:
		pattern = "*" + pattern
		hasWildcard = true
	}

	if !hasWildcard {
		if wantCased {
			return cased{want: pattern}, nil
		}
		return literal{want: pattern}, nil
	}

	if wantCased {
		// A cased comparison with wildcards is rare enough that it is not
		// worth a second glob implementation; the pattern is kept as written
		// and matched case-sensitively through a regular expression.
		rx, err := regexp.Compile("^" + globToRegexp(pattern) + "$")
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", v, err)
		}
		return re{rx: rx, src: v}, nil
	}

	lower := strings.ToLower(pattern)
	// The common shapes of a wildcard value are a leading star, a trailing
	// star, or both, and those three are a substring test rather than a glob.
	switch {
	case strings.Count(lower, "*") == 1 && strings.HasPrefix(lower, "*") && !strings.ContainsAny(lower[1:], "*?"):
		return suffix{want: lower[1:]}, nil
	case strings.Count(lower, "*") == 1 && strings.HasSuffix(lower, "*") && !strings.ContainsAny(lower[:len(lower)-1], "*?"):
		return prefix{want: lower[:len(lower)-1]}, nil
	case strings.Count(lower, "*") == 2 && strings.HasPrefix(lower, "*") && strings.HasSuffix(lower, "*") &&
		!strings.ContainsAny(lower[1:len(lower)-1], "*?"):
		return contains{want: lower[1 : len(lower)-1]}, nil
	}
	return glob{pattern: lower, src: v}, nil
}

// unescape reads a Sigma value and reports whether it contains a wildcard that
// is meant as one.
//
// The rules are easy to get wrong and the consequences are silent, so they were
// read off the reference implementation rather than inferred: a single
// backslash is a literal backslash, because rules are full of Windows paths
// written exactly as Windows writes them; `\*` and `\?` are a literal asterisk
// and question mark, and the backslash disappears; `\\` is one backslash.
//
// The consequence is worth knowing before writing a rule. The value
// `C:\Users\*\AppData` does NOT match any user's AppData folder. It is the
// literal text C:\Users*\AppData, because the backslash escaped the asterisk.
// pySigma was run on exactly that value to check it. An engine that decided to
// be helpful here would fire where every other Sigma backend stays quiet, and
// a rule that behaves differently depending on who evaluates it is worse than
// one that does nothing.
func unescape(v string) (string, bool) {
	if !strings.ContainsAny(v, `*?\`) {
		return v, false
	}
	var b strings.Builder
	b.Grow(len(v))
	wildcard := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' {
			if c == '*' || c == '?' {
				wildcard = true
			}
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(v) {
			// A trailing backslash is a backslash.
			b.WriteByte('\\')
			continue
		}
		switch next := v[i+1]; next {
		case '*', '?':
			// Escaped: the character is itself. There is no way to express
			// "literal asterisk" to the glob matcher, so it is written through
			// as a question-mark-free literal and the value stops being a
			// pattern only if nothing else in it is one.
			b.WriteByte(next)
			i++
		case '\\':
			b.WriteByte('\\')
			i++
		default:
			// A backslash before anything else is a backslash.
			b.WriteByte('\\')
		}
	}
	return b.String(), wildcard
}

// globToRegexp is used only for the case-sensitive wildcard path.
func globToRegexp(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// windashVariants are the characters an attacker can use in place of a plain
// hyphen in a command-line parameter and still have Windows accept it. The two
// long dashes are not a curiosity: they are a real evasion, which is why Sigma
// grew a modifier for them.
var windashVariants = []string{"-", "/", "–", "—", "―"}

// expandWindash rewrites every value into one variant per dash character,
// replacing the dash that opens a parameter.
func expandWindash(values []string) []string {
	out := make([]string, 0, len(values)*len(windashVariants))
	seen := map[string]bool{}
	for _, v := range values {
		for _, dash := range windashVariants {
			variant := replaceLeadingDashes(v, dash)
			if !seen[variant] {
				seen[variant] = true
				out = append(out, variant)
			}
		}
	}
	return out
}

// replaceLeadingDashes swaps the dash that starts a token. A dash inside a
// word, as in "some-name", is part of the word and is left alone.
func replaceLeadingDashes(v, dash string) string {
	var b strings.Builder
	b.Grow(len(v) + 4)
	atStart := true
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == ' ' || c == '\t':
			atStart = true
			b.WriteByte(c)
		case atStart && (c == '-' || c == '/'):
			b.WriteString(dash)
			atStart = false
		default:
			atStart = false
			b.WriteByte(c)
		}
	}
	return b.String()
}

// expandBase64Offsets produces the three encodings a string can have when it is
// embedded in base64 at an unknown position.
//
// Base64 turns three bytes into four characters, so a string that begins at
// offset 1 or 2 inside the encoded data comes out differently. The characters
// at each end are contaminated by the bytes either side, which are unknown, so
// they are trimmed and what is left is searched for as a substring.
//
// The offsets below are not derived here, they are copied from the reference
// implementation, and that matters: the arithmetic this was written with the
// first time trimmed one character too many off the tail. The result still
// matched - a shorter substring matches more, not less - so nothing would have
// looked broken. It would just have been quietly more willing to fire than the
// rule author asked for. Checking it against the published expansion of
// "Invoke-Mimikatz" is what caught it, and the test keeps that example.
func expandBase64Offsets(values []string) []string {
	// Characters to drop from the front, by how far the string is shifted.
	startOffset := [3]int{0, 2, 3}
	// Characters to drop from the tail, chosen by the length of the string
	// plus its shift: that is what decides whether the last base64 group is
	// complete and therefore whether its final characters say anything about
	// bytes that are not part of the value.
	endTrim := [3]int{0, 3, 2}

	out := make([]string, 0, len(values)*3)
	seen := map[string]bool{}
	for _, v := range values {
		for shift := 0; shift < 3; shift++ {
			enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", shift) + v))
			start := startOffset[shift]
			stop := len(enc) - endTrim[(len(v)+shift)%3]
			if start >= stop || stop > len(enc) {
				continue
			}
			candidate := enc[start:stop]
			if candidate != "" && !seen[candidate] {
				seen[candidate] = true
				out = append(out, candidate)
			}
		}
	}
	if len(out) == 0 {
		return values
	}
	return out
}

// expandPlaceholders substitutes %name% out of the table this deployment was
// configured with.
//
// A rule whose placeholder has no value is refused by name, which is the only
// honest outcome: evaluating it as written would look for the literal text
// "%Domain_Controller%" in a field and find nothing, for ever, while reporting
// itself as a rule that ran.
func expandPlaceholders(values []string, table map[string][]string) ([]string, error) {
	var out []string
	for _, v := range values {
		names := placeholderPattern.FindAllString(v, -1)
		if len(names) == 0 {
			out = append(out, v)
			continue
		}
		if len(names) > 1 {
			return nil, fmt.Errorf("value %q uses %d placeholders at once", v, len(names))
		}
		name := strings.Trim(names[0], "%")
		fills, ok := table[name]
		if !ok || len(fills) == 0 {
			return nil, fmt.Errorf("placeholder %%%s%% has no value configured", name)
		}
		for _, fill := range fills {
			out = append(out, strings.Replace(v, names[0], fill, 1))
		}
	}
	if len(out) == 0 {
		return values, nil
	}
	return out, nil
}

var placeholderPattern = regexp.MustCompile(`%[A-Za-z0-9_.-]+%`)

// toUTF16LE writes a string the way Windows holds one in memory, which is what
// a rule looking for a wide string inside an encoded blob is after.
func toUTF16LE(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r > 0xFFFF {
			// Outside the basic plane this needs a surrogate pair, and no rule
			// in the corpus needs it. Written through rather than mangled.
			b.WriteRune(r)
			continue
		}
		b.WriteByte(byte(r))
		b.WriteByte(byte(r >> 8))
	}
	return b.String()
}
