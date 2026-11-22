// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// maxRegistryFile is the largest gate registry file the CLI reads.
const maxRegistryFile = 1 << 20

var revisionRE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

const contractUsage = `usage: factory contract <command>

commands:
  schema                         print the contract JSON Schema
  validate [flags]               validate the contracts in a checkout
  explain [flags] <path>         show every effective value for a path and its source
  trust-digest [flags]        print the digest of the CLI's baseline and defaults

Run "factory contract <command> -h" for the flags of a command.
`

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// contractOptions are the flags shared by validate and explain.
//
// The install defaults and the baseline below are CLI defaults. WI-07's
// install config replaces them; until then they let a developer or CI job run
// the same checks the factory runs.
type contractOptions struct {
	root                     string
	revision                 string
	knownAgents              stringList
	staleDays, abandonedDays int
	reviewBudgetLines        int
	changed                  stringList
	registry                 string
	noRegistry               bool
	trustedDigest            string
	asJSON                   bool
}

func newContractFlags(name string, stderr io.Writer) (*flag.FlagSet, *contractOptions) {
	o := &contractOptions{}
	fs := flag.NewFlagSet("factory contract "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.root, "root", ".", "directory holding the checkout to read contracts from")
	fs.StringVar(&o.revision, "revision", "", "full commit ID (40 or 64 hex digits) the checkout is at (required)")
	fs.Var(&o.knownAgents, "known-agent", "agent name a contract may list under agents.verify (repeatable)")
	fs.IntVar(&o.staleDays, "switch-stale-days", 30, "install default for overrides.switchStaleDays")
	fs.IntVar(&o.abandonedDays, "switch-abandoned-days", 30, "install default for overrides.switchAbandonedDays")
	fs.IntVar(&o.reviewBudgetLines, "review-budget-lines", 300, "install default for overrides.reviewBudgetLines")
	return fs, o
}

func (o *contractOptions) baseline() contract.Baseline {
	return contract.Baseline{
		Reviewers:        []string{"pr-reviewer", "security-reviewer"},
		PRReviewer:       "pr-reviewer",
		SecurityReviewer: "security-reviewer",
		Protected:        []string{".github/workflows/**", ".github/actions/**", "CODEOWNERS"},
		KnownAgents:      o.knownAgents,
	}
}

func (o *contractOptions) defaults() contract.Defaults {
	return contract.Defaults{
		SwitchStaleDays: o.staleDays, SwitchAbandonedDays: o.abandonedDays, ReviewBudgetLines: o.reviewBudgetLines,
	}
}

// parseFlags parses args with the flag package's own error output turned off:
// it echoes the offending argument, which is caller input, raw. The error is
// returned instead and escaped where it is printed (see errorText). On any
// failure the usage text and the flag defaults go to stderr.
func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer, usage string) error {
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	err := fs.Parse(args)
	if err == nil {
		return nil
	}
	fmt.Fprint(stderr, usage)
	fs.SetOutput(stderr)
	fs.PrintDefaults()
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return fmt.Errorf("%w: %w", errUsage, err)
}

// usageError prints usage to stderr and returns an error that wraps errUsage.
func usageError(stderr io.Writer, usage, format string, args ...any) error {
	fmt.Fprint(stderr, usage)
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

// runContract runs "factory contract ...".
func runContract(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError(stderr, contractUsage, "no contract command given")
	}
	switch args[0] {
	case "schema":
		if len(args) != 1 {
			return usageError(stderr, contractUsage, "schema takes no arguments")
		}
		if _, err := stdout.Write(contract.SchemaJSON()); err != nil {
			return fmt.Errorf("write schema: %w", err)
		}
		return nil
	case "validate":
		return runValidate(ctx, args[1:], stdout, stderr)
	case "explain":
		return runExplain(ctx, args[1:], stdout, stderr)
	case "trust-digest":
		return runTrustDigest(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, contractUsage)
		return nil
	default:
		return usageError(stderr, contractUsage, "unknown contract command %q", args[0])
	}
}

// loadSet reads the contracts under o.root. In production the factory reads
// the tracked tree of a revision through the forge. This command reads a
// checkout with os.DirFS, so it is for developers and CI, where the checkout
// is the tracked tree.
func (o *contractOptions) loadSet(ctx context.Context, stdout io.Writer) (*contract.Set, error) {
	parser, err := contract.NewParser()
	if err != nil {
		return nil, fmt.Errorf("create parser: %w", err)
	}
	set, err := contract.Load(ctx, os.DirFS(o.root), parser, o.revision)
	if err != nil {
		return nil, reportProblems(stdout, err)
	}
	return set, nil
}

// reportProblems prints the problems in err, if it has any, one per line, and
// returns an error that says how many. Other errors pass through.
func reportProblems(stdout io.Writer, err error) error {
	var ve *contract.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	for _, p := range ve.Problems {
		fmt.Fprintln(stdout, p.String()) // Problem text is already escaped
	}
	return fmt.Errorf("contract validation failed: %d problem(s)", len(ve.Problems))
}

const validateUsage = `usage: factory contract validate --revision <commit> (--gate-registry <file> | --no-gate-registry) [flags]

Validate the contracts in a checkout (default "."). Problems are printed one
per line to stdout and the exit status is non-zero if there are any.

With --changed, only the changed contracts, their ancestors and descendants are
validated, but only if --trusted-digest matches the digest that
"factory contract trust-digest" prints for the same flags. Without it every
contract is validated, because the unchanged ones were valid only under a
baseline that is not known to be this one.

`

func runValidate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs, o := newContractFlags("validate", stderr)
	fs.Var(&o.changed, "changed", "directory whose contract changed (not a file path); validates it, its ancestors and descendants (repeatable)")
	fs.StringVar(&o.registry, "gate-registry", "", "JSON file with an array of registered gate refs (producerId, workflowId, workflowRevision, checkId)")
	fs.BoolVar(&o.noRegistry, "no-gate-registry", false, "explicitly skip checking gates against a registry")
	fs.StringVar(&o.trustedDigest, "trusted-digest", "", "digest of the baseline and defaults the unchanged contracts were validated under")
	if err := parseFlags(fs, args, stderr, validateUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return usageError(stderr, validateUsage, "unexpected argument %q", fs.Arg(0))
	}
	if !revisionRE.MatchString(o.revision) {
		return usageError(stderr, validateUsage, "--revision must be a full 40 or 64 digit lowercase hex commit ID")
	}
	switch {
	case o.registry != "" && o.noRegistry:
		return usageError(stderr, validateUsage, "--gate-registry and --no-gate-registry are exclusive")
	case o.registry == "" && !o.noRegistry:
		return usageError(stderr, validateUsage, "give --gate-registry <file>, or --no-gate-registry to skip the registry check")
	}
	if o.trustedDigest != "" && len(o.changed) == 0 {
		return usageError(stderr, validateUsage, "--trusted-digest applies only with --changed")
	}
	var reg contract.GateRegistry
	if o.registry != "" {
		r, err := readRegistry(o.registry)
		if err != nil {
			return err
		}
		reg = r
	} else {
		fmt.Fprintln(stderr, "note: gates were not checked against a registry (--no-gate-registry)")
	}
	set, err := o.loadSet(ctx, stdout)
	if err != nil {
		return err
	}
	opts := contract.ChangeOptions{Changed: o.changed, Registry: reg, TrustedDigest: o.trustedDigest}
	// Without --changed an empty digest makes this a full validation, in one
	// call, so every problem and every unregistered gate is reported together.
	sc, verr := contract.ValidateChanged(ctx, set, o.baseline(), o.defaults(), opts)
	switch {
	case errors.Is(verr, pathglob.ErrInvalidPath):
		return usageError(stderr, validateUsage, "--changed: %v", verr)
	case verr != nil:
		return reportProblems(stdout, verr)
	}
	if len(o.changed) == 0 {
		fmt.Fprintf(stdout, "ok: checked %d contracts\n", len(sc.Checked))
		return nil
	}
	if sc.Full {
		fmt.Fprintln(stderr, "note: the trusted digest is missing or does not match this baseline; validated every contract")
	}
	fmt.Fprintf(stdout, "ok: checked %d of %d contracts\n", len(sc.Checked), len(set.Dirs()))
	return nil
}

const trustDigestUsage = `usage: factory contract trust-digest [flags]

Print the digest of the baseline and install defaults this CLI uses, which
"factory contract validate --trusted-digest" compares against. Pass the
same --known-agent and default flags you pass to validate.

`

func runTrustDigest(args []string, stdout, stderr io.Writer) error {
	fs, o := newContractFlags("trust-digest", stderr)
	if err := parseFlags(fs, args, stderr, trustDigestUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return usageError(stderr, trustDigestUsage, "unexpected argument %q", fs.Arg(0))
	}
	_, err := fmt.Fprintln(stdout, contract.TrustDigest(o.baseline(), o.defaults()))
	return err
}

const explainUsage = `usage: factory contract explain --revision <commit> [flags] <path>

Show every effective value for one repository path and the contract that set
it. Flags must come before the path.

`

func runExplain(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs, o := newContractFlags("explain", stderr)
	fs.BoolVar(&o.asJSON, "json", false, "print the explanation as JSON")
	if err := parseFlags(fs, args, stderr, explainUsage); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return usageError(stderr, explainUsage, "want exactly one path")
	}
	if !revisionRE.MatchString(o.revision) {
		return usageError(stderr, explainUsage, "--revision must be a full 40 or 64 digit lowercase hex commit ID")
	}
	set, err := o.loadSet(ctx, stdout)
	if err != nil {
		return err
	}
	p, err := contract.Compile(set, o.baseline(), o.defaults())
	if err != nil {
		return reportProblems(stdout, err)
	}
	ex, err := p.Explain(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("explain: %w", err)
	}
	if o.asJSON {
		data, err := json.Marshal(ex)
		if err != nil {
			return fmt.Errorf("encode explanation: %w", err)
		}
		_, err = fmt.Fprintf(stdout, "%s\n", data)
		return err
	}
	return contract.WriteExplanation(stdout, ex)
}

// gateRegistry is the contract.GateRegistry the CLI uses: a fixed list read
// from a file.
type gateRegistry map[contract.GateRef]bool

func (r gateRegistry) Registered(_ context.Context, ref contract.GateRef) (bool, error) {
	return r[ref], nil
}

const (
	fieldProducerID = "producerId"
	fieldWorkflowID = "workflowId"
	fieldRevision   = "workflowRevision"
	fieldCheckID    = "checkId"
)

// readRegistry reads a JSON array of gate refs, strictly: a file over 1 MiB,
// trailing data, an unknown, duplicate or case-variant key, a missing or empty
// field, or a revision that is not 40 or 64 lowercase hex digits is an error.
func readRegistry(name string) (gateRegistry, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open gate registry: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRegistryFile+1))
	if err != nil {
		return nil, fmt.Errorf("read gate registry: %w", err)
	}
	if len(data) > maxRegistryFile {
		return nil, fmt.Errorf("gate registry %q is larger than %d bytes", name, maxRegistryFile)
	}
	reg, err := decodeRegistry(data)
	if err != nil {
		return nil, fmt.Errorf("decode gate registry %q: %w", name, err)
	}
	return reg, nil
}

func decodeRegistry(data []byte) (gateRegistry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(dec, '['); err != nil {
		return nil, err
	}
	reg := gateRegistry{}
	for i := 0; dec.More(); i++ {
		ref, err := decodeRegistryEntry(dec)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		reg[ref] = true
	}
	if err := expectDelim(dec, ']'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the array")
	}
	return reg, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("want %q, got %v", rune(want), tok)
	}
	return nil
}

// decodeRegistryEntry reads one object token by token, so a duplicate key is
// seen, and checks every field.
func decodeRegistryEntry(dec *json.Decoder) (contract.GateRef, error) {
	var zero contract.GateRef
	if err := expectDelim(dec, '{'); err != nil {
		return zero, err
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return zero, err
		}
		key, _ := tok.(string)
		if !slices.Contains([]string{fieldProducerID, fieldWorkflowID, fieldRevision, fieldCheckID}, key) {
			return zero, fmt.Errorf("unknown field %q (keys are case-sensitive)", key)
		}
		if _, dup := fields[key]; dup {
			return zero, fmt.Errorf("duplicate field %q", key)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return zero, err
		}
		fields[key] = raw
	}
	if err := expectDelim(dec, '}'); err != nil {
		return zero, err
	}
	var ref contract.GateRef
	for _, key := range []string{fieldProducerID, fieldWorkflowID, fieldRevision, fieldCheckID} {
		raw, ok := fields[key]
		if !ok {
			return zero, fmt.Errorf("missing field %q", key)
		}
		var err error
		switch key {
		case fieldProducerID:
			err = json.Unmarshal(raw, &ref.ProducerID)
		case fieldWorkflowID:
			err = json.Unmarshal(raw, &ref.WorkflowID)
		case fieldRevision:
			err = json.Unmarshal(raw, &ref.WorkflowRevision)
		case fieldCheckID:
			err = json.Unmarshal(raw, &ref.CheckID)
		}
		if err != nil {
			return zero, fmt.Errorf("field %q: %w", key, err)
		}
	}
	for key, v := range map[string]string{
		fieldProducerID: ref.ProducerID, fieldWorkflowID: string(ref.WorkflowID), fieldCheckID: ref.CheckID,
	} {
		if v == "" {
			return zero, fmt.Errorf("field %q is empty", key)
		}
	}
	if !revisionRE.MatchString(ref.WorkflowRevision) {
		return zero, errors.New(`field "workflowRevision" must be 40 or 64 lowercase hex digits`)
	}
	return ref, nil
}
