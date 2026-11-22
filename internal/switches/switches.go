// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package switches detects the feature switches a repository defines, checks that new ones default off, and
// renders the switch records GitHub shows (FLG-2, FLG-3). It is pure: it reads an [io/fs.FS] at one revision and
// never calls a forge. Every repository file is untrusted input (SEC-1), so parsing is strict and bounded and
// every repository-supplied string is escaped before it is shown.
package switches

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// Errors.
var (
	// ErrTooLarge means a [Limits] budget was exceeded. Detect then returns no [Set], never a partial one.
	ErrTooLarge = errors.New("switches: tree exceeds a scan limit")
	// ErrUnsupportedTree means the tree cannot report symlinks without following them ([io/fs.ReadLinkFS]).
	ErrUnsupportedTree = errors.New("switches: tree cannot report symlinks")
	// ErrInvalidLimits means a [Limits] field is not positive. The zero value is invalid.
	ErrInvalidLimits = errors.New("switches: invalid limits")
)

// Limits bound one [Detect]. Every field must be positive.
type Limits struct {
	// MaxEntries is the most tree entries (files and directories) the scan may visit.
	MaxEntries int
	// MaxFileBytes is the largest candidate file. A larger one is a too-large problem, as it cannot be probed.
	MaxFileBytes int
	// MaxTotalBytes is the most bytes of candidate files the scan may read.
	MaxTotalBytes int
	// MaxDepth is the deepest JSON nesting, counting the top-level object as 1.
	MaxDepth int
	// MaxFlagsPerFile is the most flags one flagd file or manifest may define.
	MaxFlagsPerFile int
	// MaxDefinitionsPerKey is the most definitions (sources) of one switch key. It bounds the work to compare
	// them. A tree that defines one key more often is [ErrTooLarge].
	MaxDefinitionsPerKey int
	// MaxNodes is the most values visited while probing one file, counting every expansion of a YAML alias.
	// More is a too-large problem for that file.
	MaxNodes int
}

// DefaultLimits returns the limits of the design: 16 MiB per file (the git tree serves at most 10 MiB, so every file
// it serves is probed in full), 512 MiB in all, depth 64, 10,000 flags per file, 64 definitions per key and a
// million nodes per file.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:           200_000,
		MaxFileBytes:         16 << 20,
		MaxTotalBytes:        512 << 20,
		MaxDepth:             64,
		MaxFlagsPerFile:      10_000,
		MaxDefinitionsPerKey: 64,
		MaxNodes:             1_000_000,
	}
}

func (l Limits) valid() bool {
	return l.MaxEntries > 0 && l.MaxFileBytes > 0 && l.MaxTotalBytes > 0 && l.MaxDepth > 0 && l.MaxFlagsPerFile > 0 && l.MaxDefinitionsPerKey > 0 && l.MaxNodes > 0
}

// Kind is the kind of source a [Definition] came from.
type Kind string

// Source kinds.
const (
	KindFlagd    Kind = "flagd"
	KindManifest Kind = "manifest"
)

// Type is the value type of a switch. flagd has boolean, string, number and object. The manifest also has
// integer and float, which are compatible with flagd's number.
type Type string

// Switch value types.
const (
	TypeBoolean Type = "boolean"
	TypeString  Type = "string"
	TypeNumber  Type = "number"
	TypeInteger Type = "integer"
	TypeFloat   Type = "float"
	TypeObject  Type = "object"
)

// State is a flagd flag's state.
type State string

// flagd states.
const (
	StateEnabled  State = "ENABLED"
	StateDisabled State = "DISABLED"
)

// Definition is what one source says about one switch.
type Definition struct {
	// Path is the repository path of the source file. A source embedded in a string of another file has the path
	// "file#/json/pointer" of that string.
	Path string
	Kind Kind
	Type Type
	// Variants maps variant name to value, for flagd. It is nil for the manifest. Values are bool, string,
	// json.Number or map[string]any.
	Variants map[string]any
	// DefaultVariant is the flagd defaultVariant. It is empty when HasDefaultVariant is false.
	DefaultVariant    string
	HasDefaultVariant bool
	// Default is the resolved default value: the named variant's value for flagd, defaultValue for the
	// manifest. HasDefault is false when flagd has no defaultVariant, so the code default applies.
	Default    any
	HasDefault bool
	State      State // flagd only
	// HasTargeting is true when the flag has a "targeting" key at all, even an empty one. Fail closed.
	HasTargeting bool
	Description  string
	// Invalid is set when the definition had a problem (also reported in [Set.Problems]).
	Invalid bool

	targetingSig string // canonical JSON of targeting, to tell two flagd files apart
	metaSig      string // canonical JSON of metadata
	fileSig      string // canonical JSON of the file's $evaluators and top-level metadata, which change what a flag means
	sig          string // everything that makes two flagd definitions equal, computed once by finalize
	defSig       string // canonical JSON of Default, or "-"
}

// finalize computes the signatures. It runs once, when a definition is added to a switch, so comparing
// definitions never re-encodes them.
func (d *Definition) finalize() {
	d.sig = canon([]any{d.Type, d.State, d.Variants, d.HasDefaultVariant, d.DefaultVariant, d.HasTargeting, d.targetingSig, d.metaSig, d.fileSig})
	d.defSig = "-"
	if d.HasDefault {
		d.defSig = canon(d.Default)
	}
}

// Switch is a key and every definition of it. Definitions are sorted by path.
type Switch struct {
	Key         string
	Definitions []Definition
}

// Code classifies a [Problem].
type Code string

// Problem codes.
const (
	CodeSyntax          Code = "syntax"
	CodeEncoding        Code = "encoding"
	CodeDuplicateKey    Code = "duplicate-key"
	CodeTooDeep         Code = "too-deep"
	CodeUnknownKey      Code = "unknown-key"
	CodeSchema          Code = "schema"
	CodeSymlink         Code = "symlink"
	CodeTooLarge        Code = "too-large"
	CodeAmbiguousConfig Code = "ambiguous-config"
	CodeManifestPath    Code = "manifest-path"
	CodeUnreadable      Code = "unreadable"
	// CodeNonCanonicalArray is the array form of "flags", which flagd accepts but this check does not.
	CodeNonCanonicalArray Code = "non-canonical-array"
	// CodeNonCanonicalEffective means the flags flagd would serve from a source differ from its canonical flags.
	CodeNonCanonicalEffective Code = "non-canonical-effective"
)

// Problem is a defect in one source file. A repository with any problem cannot be trusted to say which switches
// it defines, so [Compare] returns [VerdictError].
type Problem struct {
	Path    string // repository path, escaped
	Pointer string // JSON pointer into the file, escaped; empty for the whole file
	Code    Code
	Message string // escaped and bounded, safe to print on one line
}

// OpaqueEntry is a tree entry the scan cannot read: a gitlink (submodule), or a symlink that may lead to a
// directory. The deployed checkout may hold flag files behind it that this scan never sees.
type OpaqueEntry struct {
	Path string // escaped
	Kind string // "gitlink" or "symlink"

	raw    string // repository path as in the tree
	target string // symlink target as in the tree; empty for a gitlink, whose commit the tree does not expose
}

// Set is what [Detect] found at one revision. Problems and Opaque are sorted, and so are the keys of Switches
// when ranged with [Set.Keys]. Only a successful Detect makes a usable Set: [Compare] returns [VerdictError]
// for any other, such as the zero value.
type Set struct {
	Switches map[string]Switch
	Problems []Problem
	Opaque   []OpaqueEntry

	complete bool
}

// Keys returns the switch keys in sorted order.
func (s Set) Keys() []string {
	keys := make([]string, 0, len(s.Switches))
	for k := range s.Switches {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Status is the verdict on one switch's default.
type Status string

// Statuses, following the design's default-off rules.
const (
	// StatusDefaultOff means every source says boolean, ENABLED, off by default, with no targeting.
	StatusDefaultOff Status = "default-off"
	// StatusDefaultOn means a source says the switch is on by default.
	StatusDefaultOn Status = "default-on"
	// StatusUnproven means off cannot be shown: the flag is DISABLED, has no default variant, or has targeting.
	StatusUnproven Status = "unproven-default"
	// StatusNotBoolean means a source defines a switch that is not a boolean.
	StatusNotBoolean Status = "not-boolean"
	// StatusConflicting means two sources disagree.
	StatusConflicting Status = "conflicting"
	// StatusInvalid means a definition had a problem.
	StatusInvalid Status = "invalid"
)

// Status applies the default-off rules. The first rule that matches wins: invalid, conflicting, not-boolean,
// default-on, unproven-default, default-off. A switch with no definition is invalid. A switch with no flagd
// definition is unproven-default: the manifest does not set the value any SDK evaluates, so nothing here shows the
// runtime default.
func (s Switch) Status() Status {
	if len(s.Definitions) == 0 {
		return StatusInvalid
	}
	for i := range s.Definitions {
		if s.Definitions[i].Invalid {
			return StatusInvalid
		}
	}
	if s.conflicting() {
		return StatusConflicting
	}
	for i := range s.Definitions {
		if s.Definitions[i].Type != TypeBoolean {
			return StatusNotBoolean
		}
	}
	hasFlagd := false
	unproven := false
	for i := range s.Definitions {
		d := &s.Definitions[i]
		if d.HasDefault && d.Default == true {
			return StatusDefaultOn
		}
		if d.Kind == KindFlagd {
			hasFlagd = true
			unproven = unproven || d.State != StateEnabled || !d.HasDefault || d.HasTargeting
		}
	}
	if unproven || !hasFlagd {
		return StatusUnproven
	}
	return StatusDefaultOff
}

// hasFlagd reports whether any source of the switch is a flagd file.
func (s Switch) hasFlagd() bool {
	for i := range s.Definitions {
		if s.Definitions[i].Kind == KindFlagd {
			return true
		}
	}
	return false
}

// conflicting reports whether two definitions disagree. Every comparison is against the first definition of a
// kind, because equality is transitive, so the cost is linear in the definitions. flagd files must have the same
// signature (everything but path and description). A manifest must have a compatible type and the same default as
// the first flagd file and the first manifest.
func (s Switch) conflicting() bool {
	var firstFlagd, firstManifest *Definition
	for i := range s.Definitions {
		d := &s.Definitions[i]
		if d.Kind == KindFlagd {
			if firstFlagd == nil {
				firstFlagd = d
			} else if d.sig != firstFlagd.sig {
				return true
			}
		} else if firstManifest == nil {
			firstManifest = d
		}
	}
	for i := range s.Definitions {
		d := &s.Definitions[i]
		if d.Kind == KindFlagd {
			continue
		}
		if !agree(firstManifest, d) || (firstFlagd != nil && !agree(firstFlagd, d)) {
			return true
		}
	}
	return false
}

// agree reports whether two definitions of different or manifest kind have compatible types and equal defaults.
func agree(a, b *Definition) bool {
	return compatible(a.Type, b.Type) && (!a.HasDefault || !b.HasDefault || a.defSig == b.defSig)
}

func compatible(a, b Type) bool {
	num := func(t Type) bool { return t == TypeNumber || t == TypeInteger || t == TypeFloat }
	return a == b || (num(a) && num(b))
}

// canon renders a decoded value as canonical JSON (Go sorts map keys). It is used only to compare values.
func canon(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "!" + err.Error()
	}
	return strings.Clone(string(b))
}
