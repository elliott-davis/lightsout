// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// Field names used in problem pointers.
const (
	fieldPaths    = "paths"
	fieldWritable = "writable"
	fieldReadOnly = "readOnly"
	fieldGates    = "gates"
	stageVerify   = "verify"
	stageUnion    = "union"
)

// tree is the compiled contracts of a Set. A contract is identified by the
// dirKey of each segment of its directory, so stack membership is one lookup
// per prefix and every stack is a chain.
type tree struct {
	levels  map[string]*level // by directory as written
	byKey   map[string]*level // by canonical key; the first of a colliding pair
	collide map[string]string // directory -> the earlier directory with the same key
	dirs    []string          // sorted by depth, then path
}

// keyPrefixes returns the join of the first i keys for i = 0 .. len(keys)-1:
// the canonical keys of the directories above something with these keys.
func keyPrefixes(keys []string) []string {
	out := make([]string, len(keys))
	for i := 1; i < len(keys); i++ {
		out[i] = strings.Join(keys[:i], "/")
	}
	return out
}

// stack returns the contracts on the stack of the path with forms f, root to
// leaf: the contract at each proper key-prefix of the path.
func (t *tree) stack(f pathForms) []*level {
	var out []*level
	for _, prefix := range keyPrefixes(f.keys) {
		if l, ok := t.byKey[prefix]; ok {
			out = append(out, l)
		}
	}
	return out
}

// ancestors returns the contracts above l, root first, not including l: those
// at a proper key-prefix of l's directory.
func (t *tree) ancestors(l *level) []*level {
	if l.dir == "" {
		return nil
	}
	var out []*level
	for _, prefix := range keyPrefixes(l.keys) {
		if a, ok := t.byKey[prefix]; ok && a != l {
			out = append(out, a)
		}
	}
	return out
}

func dirDepth(dir string) int {
	if dir == "" {
		return 0
	}
	return strings.Count(dir, "/") + 1
}

// buildTree compiles every contract in set. A contract that fails to compile
// is left out of the tree and reported.
func buildTree(set *Set) (*tree, []Problem) {
	t := &tree{levels: map[string]*level{}, byKey: map[string]*level{}, collide: map[string]string{}}
	var problems []Problem
	for _, dir := range set.Dirs() {
		c, _ := set.Get(dir)
		l, ps := buildLevel(dir, c)
		problems = append(problems, ps...)
		if l != nil {
			t.levels[dir] = l
			t.dirs = append(t.dirs, dir)
		}
	}
	slices.SortFunc(t.dirs, func(a, b string) int {
		if c := dirDepth(a) - dirDepth(b); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	for _, dir := range t.dirs {
		l := t.levels[dir]
		if prev, ok := t.byKey[l.keyStr]; ok {
			t.collide[dir] = prev.dir
			continue
		}
		t.byKey[l.keyStr] = l
	}
	return t, problems
}

func derefList(l *[]string) []string {
	if l == nil {
		return nil
	}
	return *l
}

// buildLevel compiles and copies one contract. A Set built by NewSet may hold
// hand-built contracts that never went through the Parser.
func buildLevel(dir string, c *Contract) (*level, []Problem) {
	file := filePath(dir)
	var problems []Problem
	l := &level{
		dir: dir, file: file,
		hasWrite: c.Paths.Writable != nil, hasGen: c.Paths.Generated != nil,
		verify: slices.Clone(c.Gates.Verify), union: slices.Clone(c.Gates.Union),
		agents: slices.Clone(c.Agents.Verify),
	}
	if c.LightsOn != nil {
		v := *c.LightsOn
		l.lightsOn = &v
	}
	l.overrides = Overrides{
		SwitchStaleDays:     copyPtr(c.Overrides.SwitchStaleDays),
		SwitchAbandonedDays: copyPtr(c.Overrides.SwitchAbandonedDays),
		ReviewBudgetLines:   copyPtr(c.Overrides.ReviewBudgetLines),
	}
	if c.Gates.DarkMergeOracle != nil {
		o := *c.Gates.DarkMergeOracle
		o.Observables = slices.Clone(o.Observables)
		l.oracle = &o
	}
	if dir != "" {
		for seg := range strings.SplitSeq(dir, "/") {
			l.keys = append(l.keys, dirKey(seg))
		}
		l.keyStr = strings.Join(l.keys, "/")
	}
	compile := func(name string, texts []string) []pat {
		var out []pat
		for i, s := range texts {
			p, err := compilePat(s, dir)
			if err != nil {
				problems = append(problems, Problem{
					File: file, Field: pointer([]string{fieldPaths, name, strconv.Itoa(i)}),
					Code: CodeInvalidPattern, Message: sanitize(err.Error()),
				})
				continue
			}
			out = append(out, p)
		}
		return out
	}
	l.writable = compile(fieldWritable, derefList(c.Paths.Writable))
	l.generated = compile("generated", derefList(c.Paths.Generated))
	l.readOnly = compile(fieldReadOnly, c.Paths.ReadOnly)
	l.forbidden = compile("forbidden", c.Paths.Forbidden)
	l.sensitive = compile("sensitive", c.Paths.Sensitive)
	if len(problems) > 0 {
		return nil, problems
	}
	for i := range l.writable {
		l.writableExact = append(l.writableExact, l.writable[i].form[0])
	}
	l.reach = slices.Clone(l.writableExact)
	for i := range l.readOnly {
		l.reach = append(l.reach, l.readOnly[i].form[0], l.readOnly[i].desc[0])
	}
	return l, nil
}

func copyPtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// canonicalJSON is the JSON form of c that the schema checks and the digest
// covers. A hand-built &[]string(nil) means "declared empty", as in buildLevel,
// but would marshal as null.
func canonicalJSON(c *Contract) ([]byte, error) {
	norm := *c
	if norm.Paths.Writable != nil && *norm.Paths.Writable == nil {
		norm.Paths.Writable = &[]string{}
	}
	if norm.Paths.Generated != nil && *norm.Paths.Generated == nil {
		norm.Paths.Generated = &[]string{}
	}
	return json.Marshal(&norm)
}

// validateContract validates a Contract against the embedded schema, so a
// hand-built contract is held to the same rules as a parsed one. The schema
// stays the single source of truth: the contract is marshaled back to JSON and
// checked.
//
// The schema pass is skipped for a contract the Parser built and nobody has
// changed since: the Parser stored the digest of its JSON after validating it,
// and any change to any field changes the JSON and so the digest. A hand-built
// or mutated contract has no matching digest and is validated in full.
func (p *Parser) validateContract(file string, c *Contract) []Problem {
	fail := func(msg string) []Problem {
		return []Problem{{File: file, Code: CodeSchema, Message: sanitize(msg)}}
	}
	data, err := canonicalJSON(c)
	if err != nil {
		return fail("encode contract: " + err.Error())
	}
	if c.digested && sha256.Sum256(data) == c.digest {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fail("decode contract: " + err.Error())
	}
	verr := p.schema.Validate(value)
	if verr == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(verr, &ve) {
		return fail(verr.Error())
	}
	return p.problems(file, ve)
}

// collector gathers problems and bounds the work of validation.
type collector struct {
	problems  []Problem
	budget    int64
	exhausted bool
	where     string // contract file being checked when the budget ran out
}

// full reports whether more work is pointless: the problem cap is reached
// (newValidationError keeps at most maxProblems) or the budget is spent.
func (c *collector) full() bool { return len(c.problems) >= maxProblems || c.exhausted }

// spend takes n units of work and reports whether there was budget for it.
func (c *collector) spend(n int64, where string) bool {
	if c.exhausted {
		return false
	}
	if c.budget -= n; c.budget < 0 {
		c.exhausted, c.where = true, where
		return false
	}
	return true
}

// tryspend takes n units only if the budget covers them. It never marks the
// budget exhausted, so optional work (a witness for a message) can be skipped.
func (c *collector) tryspend(n int64) bool {
	if c.exhausted || c.budget < n {
		return false
	}
	c.budget -= n
	return true
}

// validate runs the relational checks (CON-12, CON-5, AGD-3) for the contracts
// in dirs against their ancestors and the baseline. Compile passes every
// directory. WI-04's incremental validation passes only the directories in
// scope, which must be the changed contracts, their key-ancestors, their
// key-descendants and any directory whose key collides with a changed one:
// each check reads only the contract under test and the contracts above it,
// and the collision check reads its partner. Directories without a compiled
// contract are skipped.
//
// The work is bounded. A contract whose stack reaches MaxStackDepth is
// reported before any proof runs, and validation then stops. The pattern
// proofs share one budget measured in cells; when it runs out, validate stops
// with one CodeTooMany problem. A hostile tree fails closed instead of stalling.
// It also returns the work spent, in budget units.
func (p *Policy) validate(dirs []string) ([]Problem, int64) {
	c := &collector{budget: p.compileBudget}
	type job struct {
		l   *level
		anc []*level
	}
	var jobs []job
	for _, dir := range dirs {
		l, ok := p.tree.levels[dir]
		if !ok {
			continue
		}
		anc := p.tree.ancestors(l)
		if len(anc) >= MaxStackDepth {
			c.problems = append(c.problems, Problem{
				File: l.file, Code: CodeTooMany,
				Message: fmt.Sprintf("%d contracts on the stack of this contract; the limit is %d", len(anc)+1, MaxStackDepth),
			})
			continue
		}
		jobs = append(jobs, job{l, anc})
	}
	if len(c.problems) > 0 {
		return c.problems, p.compileBudget - c.budget
	}
	scope := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		scope[dir] = true
	}
	if !p.buildStacks(c, scope) {
		// Defense in depth. The scope is closed under key-ancestors, so a
		// contract in scope never sits under an unbuilt stack that is outside
		// it, and that closure is the primary guarantee. If a caller breaks
		// it anyway, a contract in scope with no stack must not pass
		// unchecked: report it. A stack that failed outside the scope is not
		// ours to report and does not stop the checks inside it.
		if len(c.problems) == 0 && !c.exhausted {
			for _, j := range jobs {
				if _, collides := p.tree.collide[j.l.dir]; j.l.data == nil && !collides {
					c.problems = append(c.problems, Problem{
						File: j.l.file, Code: CodeTooMany,
						Message: "the stack of this contract could not be built, so it was not validated",
					})
				}
			}
		}
		if len(c.problems) > 0 || c.exhausted {
			return p.finish(c)
		}
	}
	for _, j := range jobs {
		if c.full() {
			break
		}
		p.validateLevel(c, j.l, j.anc)
	}
	return p.finish(c)
}

// finish turns an exhausted budget into its problem and returns the result.
func (p *Policy) finish(c *collector) ([]Problem, int64) {
	if c.exhausted {
		c.problems = append(c.problems, Problem{
			File: c.where, Code: CodeTooMany,
			Message: "relational validation exceeded its work budget; reduce the number of patterns or the nesting",
		})
	}
	return c.problems, p.compileBudget - c.budget
}

// validation collects the problems of one contract.
type validation struct {
	l *level
	c *collector
}

func (v *validation) addf(code Code, field []string, format string, args ...any) {
	if len(v.c.problems) >= maxProblems {
		return
	}
	v.c.problems = append(v.c.problems, Problem{
		File: v.l.file, Field: pointer(field), Code: code,
		Message: sanitize(fmt.Sprintf(format, args...)),
	})
}

func (p *Policy) validateLevel(c *collector, l *level, anc []*level) {
	v := &validation{l: l, c: c}
	if prev, ok := p.tree.collide[l.dir]; ok {
		v.addf(CodeConflict, nil, "directory %s is the same as %s once case, normalization and invisible characters are ignored",
			quote(l.dir), quote(prev))
	}
	if len(anc) == 0 && !l.hasWrite {
		v.addf(CodeMissingWritable, []string{fieldPaths, fieldWritable},
			"the topmost contract on a path must declare paths.writable, even as []")
	}
	for _, a := range anc {
		if c.full() {
			return
		}
		v.checkWritable(a)
		v.checkReadOnly(a)
		v.checkGrantsInsideDeny(a)
		v.checkLightsOn(a)
	}
	v.checkOracles(anc)
	v.checkGates(0, stageVerify, l.verify)
	v.checkGates(1, stageUnion, l.union)
	for i, name := range l.agents {
		if !p.known[name] {
			v.addf(CodeUnknownAgent, []string{"agents", "verify", strconv.Itoa(i)}, "unknown agent %s", quote(name))
		}
	}
}

// containsAny reports whether some pattern in outers provably contains inner.
// When the work budget runs out it returns true, so no further problems are
// invented; validate then reports the exhaustion.
func (v *validation) containsAny(outers []pathglob.Pattern, inner pathglob.Pattern) bool {
	for _, o := range outers {
		if !v.c.spend(int64(proofCost(o, inner)), v.l.file) || pathglob.Contains(o, inner) {
			return true
		}
	}
	return false
}

// proofCost is the work of one Contains call, in the units of matchWork: it
// fills a table of outer segments by inner segments, and comparing a segment
// pair costs at most the product of their runes.
func proofCost(outer, inner pathglob.Pattern) int {
	return int(matchWork(outer.Runes(), inner.Runes()))
}

// maxWitnessOuters is how many outer patterns a witness search tries.
const maxWitnessOuters = 8

// witnessCost is the work of one pathglob.Witness call: at most 32 matches
// (16 candidates, each against both patterns) of a candidate of about the
// inner pattern's length.
func witnessCost(outer, inner pathglob.Pattern) int64 {
	cand := inner.Runes() + 4
	return 32 * (matchWork(inner.Runes(), cand) + matchWork(outer.Runes(), cand))
}

// witness finds a concrete path matched by inner and by none of outers. Every
// match it makes is charged. If the budget can't cover a step it gives up
// quietly, so the caller falls back to the "could not prove" message.
func (v *validation) witness(outers []pathglob.Pattern, inner pathglob.Pattern) (string, bool) {
	// The zero Pattern matches nothing, so it always yields a candidate.
	tries := append([]pathglob.Pattern{{}}, outers[:min(len(outers), maxWitnessOuters)]...)
	for _, o := range tries {
		if !v.c.tryspend(witnessCost(o, inner)) {
			return "", false
		}
		cand, ok := pathglob.Witness(o, inner)
		if !ok {
			continue
		}
		runes := utf8.RuneCountInString(cand)
		hit := false
		for _, x := range outers {
			if !v.c.tryspend(matchWork(x.Runes(), runes)) {
				return "", false
			}
			if x.Match(cand) {
				hit = true
				break
			}
		}
		if !hit {
			return cand, true
		}
	}
	return "", false
}

// outsideMessage explains why inner is not within outers.
func (v *validation) outsideMessage(outers []pathglob.Pattern, inner pathglob.Pattern, what, ancFile string) string {
	if c, ok := v.witness(outers, inner); ok {
		return fmt.Sprintf("%s %s is wider than %s: for example %s", what, quote(inner.String()), quote(ancFile), quote(c))
	}
	return fmt.Sprintf("could not prove that %s is within %s", quote(inner.String()), quote(ancFile)+"'s "+what)
}

// checkWritable: a child's writable patterns must fit inside every ancestor
// that declares writable. Writable is case-sensitive: only exact forms count.
func (v *validation) checkWritable(a *level) {
	if !v.l.hasWrite || !a.hasWrite {
		return
	}
	for i := range v.l.writable {
		w := v.l.writable[i].form[0]
		if v.c.full() {
			return
		}
		if !v.containsAny(a.writableExact, w) && !v.c.exhausted {
			v.addf(CodeLoosening, []string{fieldPaths, fieldWritable, strconv.Itoa(i)}, "%s",
				v.outsideMessage(a.writableExact, w, "writable paths", a.file))
		}
	}
}

// checkReadOnly: a child's readOnly patterns must stay within what an
// ancestor that declares writable can reach, counting everything below an
// ancestor readOnly match.
func (v *validation) checkReadOnly(a *level) {
	if !a.hasWrite {
		return
	}
	for i := range v.l.readOnly {
		r := v.l.readOnly[i].form[0]
		if v.c.full() {
			return
		}
		if !v.containsAny(a.reach, r) && !v.c.exhausted {
			v.addf(CodeLoosening, []string{fieldPaths, fieldReadOnly, strconv.Itoa(i)}, "%s",
				v.outsideMessage(a.reach, r, "writable and read-only paths", a.file))
		}
	}
}

// variants are the patterns and descendant patterns of a deny list, per form.
type variants struct {
	all [nForms][]pathglob.Pattern
	// distinct leaves out a variant identical to its form 0, which a child
	// pattern identical to its own form 0 has already been checked against.
	distinct [nForms][]pathglob.Pattern
}

func denyVariants(ps []pat) variants {
	var out variants
	for i := range ps {
		for k := range nForms {
			if !ps[i].hasForm[k] {
				continue
			}
			out.all[k] = append(out.all[k], ps[i].form[k], ps[i].desc[k])
			if !ps[i].same[k] {
				out.distinct[k] = append(out.distinct[k], ps[i].form[k], ps[i].desc[k])
			}
		}
	}
	return out
}

// inside reports whether x is provably inside the deny variants in any form. The
// folded forms catch a child directory that differs from the ancestor's only in case.
func (v *validation) inside(x *pat, vs variants) bool {
	for k := range nForms {
		if !x.hasForm[k] {
			continue
		}
		outers := vs.all[k]
		if x.same[k] {
			outers = vs.distinct[k]
		}
		if len(outers) > 0 && v.containsAny(outers, x.form[k]) && !v.c.exhausted {
			return true
		}
	}
	return false
}

// checkGrantsInsideDeny: a child may not grant (writable or readOnly) paths
// that an ancestor forbids, or writable paths that an ancestor made read-only.
// Partial overlap is allowed: the minimum rule keeps the ancestor's
// restriction, and globs cannot express exclusions.
func (v *validation) checkGrantsInsideDeny(a *level) {
	forbidden, readOnly := denyVariants(a.forbidden), denyVariants(a.readOnly)
	for i := range v.l.writable {
		if v.c.full() {
			return
		}
		w := &v.l.writable[i]
		switch {
		case v.inside(w, forbidden):
			v.addf(CodeLoosening, []string{fieldPaths, fieldWritable, strconv.Itoa(i)},
				"writable %s is inside %s's forbidden paths", quote(w.form[0].String()), quote(a.file))
		case v.inside(w, readOnly):
			v.addf(CodeLoosening, []string{fieldPaths, fieldWritable, strconv.Itoa(i)},
				"writable %s is inside %s's read-only paths", quote(w.form[0].String()), quote(a.file))
		}
	}
	for i := range v.l.readOnly {
		if v.c.full() {
			return
		}
		r := &v.l.readOnly[i]
		if v.inside(r, forbidden) {
			v.addf(CodeLoosening, []string{fieldPaths, fieldReadOnly, strconv.Itoa(i)},
				"read-only %s is inside %s's forbidden paths", quote(r.form[0].String()), quote(a.file))
		}
	}
}

// checkLightsOn: lightsOn can only turn on down the tree.
func (v *validation) checkLightsOn(a *level) {
	if v.l.lightsOn != nil && !*v.l.lightsOn && a.lightsOn != nil && *a.lightsOn {
		v.addf(CodeLoosening, []string{"lightsOn"}, "lightsOn false under %s, which sets it true", quote(a.file))
	}
}

// checkOracles: an oracle with the same identity as an ancestor's must keep the revision and case manifest.
func (v *validation) checkOracles(anc []*level) {
	o := v.l.oracle
	if o == nil {
		return
	}
	for _, a := range anc {
		if a.oracle != nil && a.oracle.Key() == o.Key() && oraclePin(a.oracle) != oraclePin(o) {
			v.addf(CodeConflict, []string{fieldGates, "darkMergeOracle"},
				"oracle %s is pinned to a different revision or case manifest than in %s; two pins on one path can never both pass",
				quote(o.CheckID), quote(a.file))
		}
	}
}

// checkGates checks one stage against the index of the stack above (ancestors
// and baseline): a duplicate identity in the contract, a different revision
// than the one already pinned for the same identity (CON-3), and a mandatory
// gate redeclared as advisory (CON-5). Each gate is one lookup, charged to the
// work budget.
func (v *validation) checkGates(stage int, name string, own []Gate) {
	seen := map[GateKey]bool{}
	var above map[GateKey]gateInfo
	if v.l.up != nil {
		above = v.l.up.idx[stage]
	}
	for i, g := range own {
		if !v.c.spend(1, v.l.file) {
			return
		}
		field := []string{fieldGates, name, strconv.Itoa(i)}
		if seen[g.Key()] {
			v.addf(CodeConflict, field, "gate %s is declared more than once in this contract", quote(g.CheckID))
		}
		seen[g.Key()] = true
		info, ok := above[g.Key()]
		if !ok {
			continue
		}
		if info.rev != g.WorkflowRevision {
			v.addf(CodeConflict, field,
				"gate %s is pinned to a different revision than in %s; two pins on one path can never both pass",
				quote(g.CheckID), quote(info.revSource))
		}
		if info.mandSource != "" && !g.Mandatory {
			v.addf(CodeLoosening, field, "gate %s is mandatory in %s and cannot be made advisory",
				quote(g.CheckID), quote(info.mandSource))
		}
	}
}
