package main

import (
	"fmt"
	"reflect"
	"strings"
)

// toHex converts any numeric representation of an access mask into the
// canonical "0x1010" form that Sigma rules match against.
//
// This exists for a specific, measured reason: the concrete Go type returned by
// the EVTX parser for GrantedAccess is NOT stable across library versions. In
// evtx v0.2.0 it arrives as uint32 (4112); on the main branch it arrives as
// evtx.HexInt (0x1010). Both describe the same bytes on disk.
//
// Reflection is used instead of a type switch on purpose. evtx.HexInt is
// declared as `type HexInt uint64`, and in Go a named type does not match its
// underlying type in a switch: `case uint64:` will not catch a HexInt.
// Reflection inspects the kind rather than the name, so it handles both.
//
// Without this normalisation a rule matching '0x1010' silently never fires.
func toHex(v interface{}) (string, bool) {
	if v == nil {
		return "", false
	}

	// Case 1: already a hex string.
	if s, ok := v.(string); ok {
		s = strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(s, "0x") {
			return s, true
		}
		return "", false
	}

	// Case 2: any integer, named type or not.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("0x%x", rv.Uint()), true

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := rv.Int()
		if n < 0 {
			return "", false
		}
		return fmt.Sprintf("0x%x", uint64(n)), true

	case reflect.Float32, reflect.Float64:
		// Integers that have been through JSON arrive as float64.
		f := rv.Float()
		if f < 0 || f != float64(uint64(f)) {
			return "", false
		}
		return fmt.Sprintf("0x%x", uint64(f)), true
	}

	return "", false
}
