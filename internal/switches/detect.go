// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/elliott-davis/lightsout/internal/pathglob"
	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

const (
	opScan = "scan"
	opRead = "read"

	configJSON       = ".openfeature.json"
	configYAML       = ".openfeature.yaml"
	minEmbeddedBytes = 16 // a string must be longer than this to be searched for a source
)

// scanError is an error from reading the tree. Its text escapes the path and the underlying error, which may
// echo it, while the chain keeps the original for errors.Is.
type scanError struct {
	op   string
	path string
	err  error
}

func (e *scanError) Error() string {
	return e.op + " " + escape(e.path) + ": " + escape(e.err.Error())
}

func (e *scanError) Unwrap() error { return e.err }

// Detect finds the switches the tree defines (FLG-2). It works in two stages. The principle is a wide net for
// anything flagd could load flags from, then strict canonical form, so that anything unusual fails closed.
//
// Stage 1, what is a source. A candidate is every regular file whose extension, folded to lower case with
// non-alphanumerics removed (flagd's rule), is json, yaml or yml, so "x.js-on" and "X.YAML" count. It is decoded as
// flagd decodes it: encoding/json for JSON (duplicate keys allowed, the last wins, invalid UTF-8 accepted) and
// yaml.v3 for the first document of YAML, with map keys made strings. A file the decoder rejects is skipped, because
// flagd rejects it too. A decoded document is a source if any top-level key matches "flags" under encoding/json's
// case-insensitive rule and its value is not null. Every string value of more than 16 bytes in a candidate is decoded
// the same way (JSON, then YAML), and is an embedded source if it is a source, with the path file#/json/pointer. That
// goes one level deep: an embedded source is not searched for further ones. A symlink to a regular file in the tree
// is read through, under the link's own name.
//
// Stage 2, canonical form. Every source is parsed strictly and must be canonical (see the design): exact
// lower-case keys, "flags" an object keyed by switch name (the array form is a problem), evaluator names of
// [A-Za-z0-9_-]{1,64} with non-empty object values, metadata of scalars, "$ref" only inside targeting and naming an
// evaluator of the file, no duplicate keys, no non-string YAML keys, and a YAML source that is the only document.
// Anything else is a [Problem].
//
// The OpenFeature config file (.openfeature.json or .openfeature.yaml at the root) may name an explicit manifest
// path. That file is parsed strictly as a manifest even when it holds nothing flag-like.
//
// The tree must implement [fs.ReadLinkFS], so a symlink is seen and never followed except as above. A symlink with a
// candidate name that cannot be resolved to a regular file in the tree is a problem. Gitlinks and other symlinks that
// cannot be resolved are listed in [Set.Opaque]. A file larger than MaxFileBytes, or one the tree will not serve, is
// a too-large problem. Exceeding any other [Limits] budget gives [ErrTooLarge] and no Set, except MaxNodes and
// MaxDepth while probing a file, which are problems for that file. A cancelled ctx stops the scan with its error.
func Detect(ctx context.Context, tree fs.FS, lim Limits) (Set, error) {
	if !lim.valid() {
		return Set{}, ErrInvalidLimits
	}
	if _, ok := tree.(fs.ReadLinkFS); !ok {
		return Set{}, ErrUnsupportedTree
	}
	if err := ctx.Err(); err != nil {
		return Set{}, err
	}
	sc := &scan{tree: tree, lim: lim, defs: map[string][]Definition{}}
	mpath, err := sc.manifestPath()
	if err != nil {
		return Set{}, err
	}
	sc.manifestAt = mpath
	walk := func(p string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return sc.visit(ctx, p, d, err)
	}
	if err := fs.WalkDir(tree, ".", walk); err != nil {
		return Set{}, err
	}
	if mpath != "" {
		if err := sc.manifest(mpath); err != nil {
			return Set{}, err
		}
	}
	return sc.result(), nil
}

type scan struct {
	tree       fs.FS
	lim        Limits
	manifestAt string // explicit manifest path, read separately
	entries    int
	bytes      int
	defs       map[string][]Definition
	problems   []Problem
	opaque     []OpaqueEntry
}

func (sc *scan) result() Set {
	set := Set{Switches: make(map[string]Switch, len(sc.defs)), Problems: sc.problems, Opaque: sc.opaque, complete: true}
	for key, defs := range sc.defs {
		slices.SortFunc(defs, func(a, b Definition) int {
			return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Kind, b.Kind))
		})
		set.Switches[key] = Switch{Key: key, Definitions: defs}
	}
	slices.SortFunc(set.Problems, func(a, b Problem) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Pointer, b.Pointer), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Message, b.Message))
	})
	slices.SortFunc(set.Opaque, func(a, b OpaqueEntry) int { return cmp.Compare(a.raw, b.raw) })
	return set
}

// addDef adds a definition of key, within MaxDefinitionsPerKey.
func (sc *scan) addDef(key string, d *Definition) error {
	if len(sc.defs[key]) >= sc.lim.MaxDefinitionsPerKey {
		return &scanError{op: opScan, path: d.Path, err: fmt.Errorf("more than %d definitions of one switch: %w", sc.lim.MaxDefinitionsPerKey, ErrTooLarge)}
	}
	d.finalize()
	sc.defs[key] = append(sc.defs[key], *d)
	return nil
}

// addf records a problem. The format must be static, and every string argument is escaped.
func (sc *scan) addf(p string, ptr []string, code Code, format string, args ...any) {
	for i, a := range args {
		if s, ok := a.(string); ok {
			args[i] = escape(s)
		}
	}
	sc.problems = append(sc.problems, Problem{Path: escape(p), Pointer: pointer(ptr), Code: code, Message: fmt.Sprintf(format, args...)})
}

func (sc *scan) parseProblem(p string, e *parseError) {
	sc.problems = append(sc.problems, Problem{Path: escape(p), Pointer: pointer(e.path), Code: e.code, Message: e.msg})
}

// charge spends n bytes of the total budget before they are read.
func (sc *scan) charge(p string, n int64) error {
	if int64(sc.bytes)+n > int64(sc.lim.MaxTotalBytes) {
		return &scanError{op: opRead, path: p, err: fmt.Errorf("total bytes over %d: %w", sc.lim.MaxTotalBytes, ErrTooLarge)}
	}
	sc.bytes += int(n)
	return nil
}

// read reads one file whose size is already known to be within MaxFileBytes.
func (sc *scan) read(p string, size int64) ([]byte, error) {
	if err := sc.charge(p, size); err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(sc.tree, p)
	if err != nil {
		return nil, &scanError{op: opRead, path: p, err: err}
	}
	return data, nil
}

// candidateSuffix reports whether a file name could hold a flag source: flagd's rule for the extension (see
// [asciiExtension]) gives json, yaml or yml.
func candidateSuffix(name string) bool {
	switch asciiExtension(path.Ext(name)) {
	case extJSON, "yaml", "yml":
		return true
	}
	return false
}

func isYAML(name string) bool { return asciiExtension(path.Ext(name)) != extJSON }

func (sc *scan) visit(ctx context.Context, p string, d fs.DirEntry, err error) error {
	if err != nil {
		return &scanError{op: opScan, path: p, err: err}
	}
	sc.entries++
	if sc.entries > sc.lim.MaxEntries {
		return &scanError{op: opScan, path: p, err: fmt.Errorf("more than %d entries: %w", sc.lim.MaxEntries, ErrTooLarge)}
	}
	if d.IsDir() {
		return nil
	}
	base := path.Base(p)
	switch typ := d.Type(); {
	case typ&fs.ModeSymlink != 0:
		return sc.symlink(ctx, p)
	case typ&fs.ModeIrregular != 0:
		sc.opaque = append(sc.opaque, OpaqueEntry{Path: escape(p), Kind: "gitlink", raw: p})
		return nil
	case !typ.IsRegular():
		return nil
	}
	if !candidateSuffix(base) || p == sc.manifestAt {
		return nil
	}
	info, err := d.Info()
	if err != nil {
		return &scanError{op: opScan, path: p, err: err}
	}
	return sc.probeFile(ctx, p, p, info.Size())
}

// probeFile reads the file at src and probes it as the candidate p (the same, or a symlink to src).
func (sc *scan) probeFile(ctx context.Context, p, src string, size int64) error {
	if size > int64(sc.lim.MaxFileBytes) {
		sc.addf(p, nil, CodeTooLarge, "file is larger than %d bytes and cannot be probed", sc.lim.MaxFileBytes)
		return nil
	}
	if err := sc.charge(p, size); err != nil {
		return err
	}
	data, err := fs.ReadFile(sc.tree, src)
	if err != nil {
		// The tree refuses what it will not serve, in practice a file over its own size limit.
		sc.addf(p, nil, CodeTooLarge, "the tree did not serve the file: %s", err.Error())
		return nil
	}
	return sc.candidate(ctx, p, data)
}

// symlink handles a symlink entry. One that resolves to a regular file in the tree is read through when its own
// name is a candidate. One that cannot be resolved is a problem if its name is a candidate and opaque otherwise.
func (sc *scan) symlink(ctx context.Context, p string) error {
	target, ok := sc.resolveLink(p)
	candidate := candidateSuffix(path.Base(p))
	switch {
	case !ok && candidate:
		sc.addf(p, nil, CodeSymlink, "candidate flag file is a symlink that does not resolve to a regular file in the tree")
	case !ok:
		raw, _ := fs.ReadLink(sc.tree, p)
		sc.opaque = append(sc.opaque, OpaqueEntry{Path: escape(p), Kind: "symlink", raw: p, target: raw})
	case candidate:
		info, err := fs.Lstat(sc.tree, target)
		if err != nil {
			return &scanError{op: opScan, path: p, err: err}
		}
		return sc.probeFile(ctx, p, target, info.Size())
	}
	return nil
}

// resolveLink resolves the symlink at p to a regular file in the tree. It resolves one component at a time:
// ".." may not leave the tree, and no component may be a symlink, gitlink or other irregular entry.
func (sc *scan) resolveLink(p string) (string, bool) {
	target, err := fs.ReadLink(sc.tree, p)
	if err != nil || target == "" || path.IsAbs(target) {
		return "", false
	}
	var cur []string
	if dir := path.Dir(p); dir != "." {
		cur = strings.Split(dir, "/")
	}
	for seg := range strings.SplitSeq(target, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(cur) == 0 {
				return "", false
			}
			cur = cur[:len(cur)-1]
		default:
			cur = append(cur, seg)
			info, lerr := fs.Lstat(sc.tree, strings.Join(cur, "/"))
			if lerr != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
				return "", false
			}
		}
	}
	resolved := strings.Join(cur, "/")
	info, err := fs.Lstat(sc.tree, resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return resolved, true
}

// errNodes, errDepth and errCollision stop probing one file.
var (
	errNodes     = errors.New("too many nodes")
	errDepth     = errors.New("nesting too deep")
	errCollision = errors.New("map keys collide")
)

// probe is one pass over a file's values: the nodes visited, with a context check every 1,024. The conversion of a
// YAML document and the walk for embedded sources each have their own, so no value is counted twice.
type probe struct {
	nodes    int
	max      int
	bytes    int // bytes of strings visited, so an alias of a large string cannot expand without bound
	maxBytes int
	maxDepth int
	ctxErr   func() error
}

func (sc *scan) newProbe(ctx context.Context) *probe {
	return &probe{max: sc.lim.MaxNodes, maxBytes: sc.lim.MaxFileBytes, maxDepth: sc.lim.MaxDepth, ctxErr: ctx.Err}
}

// tick counts one value. Only a container counts toward the depth, as in the strict parser.
func (b *probe) tick(v any, depth int) error {
	b.nodes++
	if b.nodes > b.max {
		return errNodes
	}
	switch t := v.(type) {
	case map[string]any, map[any]any, []any:
		if depth > b.maxDepth {
			return errDepth
		}
	case string:
		if b.bytes += len(t); b.bytes > b.maxBytes {
			return errNodes
		}
	}
	if b.nodes&1023 == 0 {
		return b.ctxErr()
	}
	return nil
}

// stringKeys converts every map[any]any under v to map[string]any with fmt.Sprint keys, as flagd's convertMapKeys
// does. Two keys that give one string are errCollision, where flagd keeps a random one.
func stringKeys(v any, depth int, b *probe) (any, error) {
	if err := b.tick(v, depth); err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			c, err := stringKeys(e, depth+1, b)
			if err != nil {
				return nil, err
			}
			t[k] = c
		}
		return t, nil
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			c, err := stringKeys(e, depth+1, b)
			if err != nil {
				return nil, err
			}
			key := fmt.Sprint(k)
			if _, dup := out[key]; dup {
				return nil, errCollision
			}
			out[key] = c
		}
		return out, nil
	case []any:
		for i, e := range t {
			c, err := stringKeys(e, depth+1, b)
			if err != nil {
				return nil, err
			}
			t[i] = c
		}
		return t, nil
	}
	return v, nil
}

// decodeYAMLDocs decodes every document of data. The first is decoded as flagd decodes a file, into a map, and
// ok is false if flagd would reject it (so the file is no source). Later documents are decoded into any, with keys
// made strings. extra reports a second document, which flagd never reads, even a broken one.
func decodeYAMLDocs(data []byte, b *probe) (docs []any, extra, ok bool, err error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for i := 0; ; i++ {
		var n yaml.Node
		if derr := dec.Decode(&n); derr != nil {
			if i > 0 && !errors.Is(derr, io.EOF) {
				extra = true
			}
			return docs, extra, i > 0 || errors.Is(derr, io.EOF), nil
		}
		if i > 0 {
			extra = true
		}
		var v any
		if i == 0 && len(n.Content) == 1 && n.Content[0].Kind == yaml.MappingNode {
			ms, decodable := decodeMapNode(&n)
			if !decodable {
				return nil, false, false, nil
			}
			v = ms
		} else if n.Decode(&v) != nil {
			if i == 0 {
				return nil, false, false, nil
			}
			continue
		}
		conv, cerr := stringKeys(v, 1, b)
		if cerr != nil {
			return nil, false, false, cerr
		}
		docs = append(docs, conv)
	}
}

// decodeMapNode decodes a YAML document into a map, as flagd does. ok is false if flagd would reject it.
func decodeMapNode(n *yaml.Node) (map[string]any, bool) {
	var ms map[string]any
	if err := n.Decode(&ms); err != nil {
		return nil, false
	}
	return ms, true
}

// lenientJSON decodes data as flagd does (and as any JSON decoder): duplicate keys allowed, the last wins, invalid
// UTF-8 accepted. ok is false if the decoder rejects it.
func lenientJSON(data []byte) (any, bool) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, false
	}
	return v, true
}

// hasFoldedKey reports whether m has a key that may be "flags" or "$evaluators" under encoding/json's matching.
// It is a cheap filter before a document is marshalled, and may say yes too often.
func hasFoldedKey(m map[string]any) bool {
	for k := range m {
		if strings.EqualFold(k, keyFlags) || strings.EqualFold(k, keyEvaluators) {
			return true
		}
	}
	return false
}

// candidate probes one candidate file's bytes: is it a source, is a FeatureFlag resource a source, and do its
// strings hold embedded sources. The file-level source test uses the first YAML document only, as flagd does. The
// search for strings and resources covers every document.
func (sc *scan) candidate(ctx context.Context, p string, data []byte) error {
	conv, walk := sc.newProbe(ctx), sc.newProbe(ctx)
	var docs []any
	extra := false
	if isYAML(p) {
		var ok bool
		var err error
		if docs, extra, ok, err = decodeYAMLDocs(data, conv); err != nil {
			return sc.probeStopped(p, err)
		} else if !ok {
			return nil
		}
	} else {
		v, ok := lenientJSON(data)
		if !ok {
			return nil
		}
		docs = []any{v}
	}
	for i, d := range docs {
		var pfx []string
		if len(docs) > 1 {
			pfx = []string{strconv.Itoa(i)}
		}
		if m, isMap := d.(map[string]any); isMap {
			if err := sc.fileDocument(p, data, m, i == 0, extra); err != nil {
				return err
			}
			if err := sc.featureFlag(p+"#"+docPointer(pfx), m); err != nil {
				return err
			}
		}
		w := &walker{sc: sc, b: walk, p: p, ptr: slices.Clone(pfx), seen: map[string]struct{}{}}
		if err := w.walk(d, 1); err != nil {
			return sc.probeStopped(p, err)
		}
	}
	return nil
}

// docPointer is the pointer of document i of a multi-document file: "/i", or "" for a single document.
func docPointer(pfx []string) string {
	if len(pfx) == 0 {
		return ""
	}
	return "/" + pfx[0]
}

// fileDocument handles the first document of a file as a possible source. A YAML file's document is marshalled to
// JSON first, as flagd does, and that is charged to the budget.
func (sc *scan) fileDocument(p string, data []byte, m map[string]any, first, extra bool) error {
	if !first {
		return nil
	}
	if !isYAML(p) {
		return sc.handle(p, string(data), func() (any, bool) { return sc.strictJSON(p, data) })
	}
	if !hasFoldedKey(m) {
		return nil
	}
	js, err := json.Marshal(m)
	if err != nil {
		return nil //nolint:nilerr // flagd cannot encode it either, so it is no source
	}
	if err := sc.charge(p, int64(len(js))); err != nil {
		return err
	}
	return sc.handle(p, string(js), func() (any, bool) { return sc.strictYAML(p, data, extra) })
}

// featureFlag ports the handling of core/pkg/sync/kubernetes/kubernetes_sync.go marshallFeatureFlagSpec: a
// FeatureFlag resource of the group core.openfeature.dev serves spec.flagSpec (marshalled as JSON) as its flag
// definition, and the older spec.featureFlagSpec. Each goes through the same pipeline as a file, from the
// evaluators on. The resource's typed conversion in the operator is not ported, so a field it would drop is kept
// here, and the canonical form refuses unknown keys.
func (sc *scan) featureFlag(base string, m map[string]any) error {
	version, _ := m["apiVersion"].(string)
	if m["kind"] != "FeatureFlag" || !strings.HasPrefix(version, "core.openfeature.dev/") {
		return nil
	}
	spec, _ := m["spec"].(map[string]any)
	for _, k := range []string{"flagSpec", "featureFlagSpec"} {
		v, ok := spec[k]
		if !ok || v == nil {
			continue
		}
		js, err := json.Marshal(v)
		if err != nil {
			continue
		}
		src := base + "/spec/" + k
		if err := sc.charge(src, int64(len(js))); err != nil {
			return err
		}
		if err := sc.handle(src, string(js), func() (any, bool) { return sc.strictJSON(src, js) }); err != nil {
			return err
		}
	}
	return nil
}

// probeStopped records that a file could not be probed in full, which fails closed.
func (sc *scan) probeStopped(p string, err error) error {
	switch {
	case errors.Is(err, errNodes):
		sc.addf(p, nil, CodeTooLarge, "file has more than %d nodes or expands to more than %d bytes of text", sc.lim.MaxNodes, sc.lim.MaxFileBytes)
	case errors.Is(err, errDepth):
		sc.addf(p, nil, CodeTooDeep, "nesting is deeper than %d", sc.lim.MaxDepth)
	case errors.Is(err, errCollision):
		sc.addf(p, nil, CodeSchema, "two YAML map keys are the same string after conversion, and flagd keeps either of them at random")
	default:
		return err
	}
	return nil
}

// strictJSON parses data strictly, recording a problem and returning false if it is not canonical JSON.
func (sc *scan) strictJSON(p string, data []byte) (any, bool) {
	doc, perr := parseJSON(data, sc.lim.MaxDepth)
	if perr != nil {
		sc.parseProblem(p, perr)
		return nil, false
	}
	return doc, true
}

// strictYAML parses data strictly with yamlsafe. A source with a second document is a problem, as flagd reads only
// the first.
func (sc *scan) strictYAML(p string, data []byte, extra bool) (any, bool) {
	if extra {
		sc.addf(p, nil, CodeSchema, "YAML source has more than one document, and flagd reads only the first")
		return nil, false
	}
	doc, yerr := yamlsafe.Decode(data, yamlsafe.Limits{MaxBytes: sc.lim.MaxFileBytes, MaxDepth: sc.lim.MaxDepth, MaxNodes: sc.lim.MaxNodes, Name: "flag file"})
	if yerr != nil {
		sc.yamlProblem(p, yerr)
		return nil, false
	}
	return doc, true
}

// handle decides whether a document, as the JSON text flagd would load, is a source, and if so parses it strictly
// and records its flags. A flagd source must also give exactly the flags flagd would serve from it.
func (sc *scan) handle(at, js string, strict func() (any, bool)) error {
	if !isFlagSource(js) {
		return nil
	}
	doc, ok := strict()
	if !ok {
		return nil
	}
	before := len(sc.problems)
	flagd, err := sc.source(at, doc)
	if err != nil || !flagd || len(sc.problems) != before {
		return err
	}
	if m, isMap := doc.(map[string]any); isMap && !canonicalMatchesEffective(m, js) {
		sc.addf(at, nil, CodeNonCanonicalEffective, "the flags flagd would serve from this source differ from its canonical flags")
	}
	return nil
}

// source records the flags of a strictly parsed source, as a flagd file or an OpenFeature manifest by its entries.
// flagd is true for a flagd source.
func (sc *scan) source(p string, doc any) (flagd bool, err error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		sc.addf(p, nil, CodeSchema, "top level must be an object")
		return false, nil
	}
	flags, _ := obj[keyFlags].(map[string]any)
	var hasFlagd, hasManifest bool
	for _, e := range flags {
		entry, isObj := e.(map[string]any)
		if !isObj {
			continue
		}
		_, hasState := entry["state"]
		_, hasVariants := entry["variants"]
		_, hasType := entry["flagType"]
		hasFlagd = hasFlagd || hasState || hasVariants
		hasManifest = hasManifest || (hasType && !hasState && !hasVariants)
	}
	switch {
	case hasFlagd && hasManifest:
		sc.addf(p, nil, CodeSchema, "file mixes flagd flags and OpenFeature manifest flags")
		return false, nil
	case hasManifest:
		return false, sc.manifestFlags(p, obj)
	}
	return true, sc.flagd(p, obj)
}

func (sc *scan) yamlProblem(p string, e *yamlsafe.Error) {
	sc.problems = append(sc.problems, Problem{Path: escape(p), Pointer: markdownSafe(e.Path), Code: yamlCode(e.Code), Message: markdownSafe(e.Message)})
}

func yamlCode(c yamlsafe.Code) Code {
	switch c {
	case yamlsafe.CodeTooLarge:
		return CodeTooLarge
	case yamlsafe.CodeSyntax:
		return CodeSyntax
	case yamlsafe.CodeUnsafeYAML, yamlsafe.CodeSchema:
		return CodeSchema
	}
	return CodeSchema
}

// walker searches a decoded document for strings that hold a source. It shares one pointer stack, and builds a
// pointer string only for a hit. Equal strings (an alias repeated many times) are decoded once.
type walker struct {
	sc   *scan
	b    *probe
	p    string
	ptr  []string
	seen map[string]struct{}
}

func (w *walker) walk(v any, depth int) error {
	if err := w.b.tick(v, depth); err != nil {
		return err
	}
	switch t := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(t)) {
			w.ptr = append(w.ptr, k)
			err := w.walk(t[k], depth+1)
			w.ptr = w.ptr[:len(w.ptr)-1]
			if err != nil {
				return err
			}
		}
	case []any:
		for i, e := range t {
			w.ptr = append(w.ptr, strconv.Itoa(i))
			err := w.walk(e, depth+1)
			w.ptr = w.ptr[:len(w.ptr)-1]
			if err != nil {
				return err
			}
		}
	case string:
		if len(t) > minEmbeddedBytes {
			if _, dup := w.seen[t]; !dup {
				w.seen[t] = struct{}{}
				return w.sc.embeddedString(w.b.ctxErr, w.p, t, w.ptr)
			}
		}
	}
	return nil
}

// embeddedString decodes a string as a candidate file would be, as JSON and then as YAML (its first document), and
// records it as a source if it is one, or holds a FeatureFlag resource. The decode is charged to the byte budget
// first. It goes one level deep: the strings of an embedded document are not searched.
func (sc *scan) embeddedString(ctxErr func() error, p, s string, ptr []string) error {
	if err := sc.charge(p, int64(len(s))); err != nil {
		return err
	}
	data := []byte(s)
	tokens := make([]string, len(ptr))
	for i, t := range ptr {
		tokens[i] = strings.NewReplacer("~", "~0", "/", "~1").Replace(t)
	}
	// The path of an embedded source is file#/pointer. The "#" is escaped for display like any other text, as \x23.
	ep := p + "#/" + strings.Join(tokens, "/")
	var m map[string]any
	var js string
	var strict func() (any, bool)
	if v, isJSON := lenientJSON(data); isJSON {
		var isMap bool
		if m, isMap = v.(map[string]any); !isMap {
			return nil
		}
		js, strict = s, func() (any, bool) { return sc.strictJSON(ep, data) }
	} else {
		b := &probe{max: sc.lim.MaxNodes, maxBytes: sc.lim.MaxFileBytes, maxDepth: sc.lim.MaxDepth, ctxErr: ctxErr}
		docs, extra, ok, err := decodeYAMLDocs(data, b)
		if err != nil {
			return sc.probeStopped(ep, err)
		}
		if !ok || len(docs) == 0 {
			return nil
		}
		var isMap bool
		if m, isMap = docs[0].(map[string]any); !isMap || !hasFoldedKey(m) && m["kind"] != "FeatureFlag" {
			return nil
		}
		out, merr := json.Marshal(m)
		if merr != nil {
			return nil //nolint:nilerr // flagd cannot encode it either
		}
		if err := sc.charge(ep, int64(len(out))); err != nil {
			return err
		}
		js, strict = string(out), func() (any, bool) { return sc.strictYAML(ep, data, extra) }
	}
	if err := sc.handle(ep, js, strict); err != nil {
		return err
	}
	return sc.featureFlag(ep, m)
}

// manifestPath returns the explicit manifest path set by the config file, or "" when there is none. A config
// problem is reported, and then no manifest is read.
func (sc *scan) manifestPath() (string, error) {
	var present []string
	for _, name := range []string{configJSON, configYAML} {
		info, err := fs.Lstat(sc.tree, name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", &scanError{op: opScan, path: name, err: err}
		}
		present = append(present, name)
		if info.Mode()&fs.ModeSymlink != 0 {
			sc.addf(name, nil, CodeSymlink, "config file is a symlink")
			return "", nil
		}
		if !info.Mode().IsRegular() || info.Size() > int64(sc.lim.MaxFileBytes) {
			sc.addf(name, nil, CodeSchema, "config file is not a regular file within %d bytes", sc.lim.MaxFileBytes)
			return "", nil
		}
	}
	switch len(present) {
	case 0:
		return "", nil
	case 2:
		sc.addf(configJSON, nil, CodeAmbiguousConfig, "both %s and %s exist, so the manifest path is ambiguous", configJSON, configYAML)
		return "", nil
	}
	name := present[0]
	info, err := fs.Lstat(sc.tree, name)
	if err != nil {
		return "", &scanError{op: opScan, path: name, err: err}
	}
	data, err := sc.read(name, info.Size())
	if err != nil {
		return "", err
	}
	doc, ok := sc.decodeConfig(name, data)
	if !ok {
		return "", nil
	}
	obj, isObj := doc.(map[string]any)
	if !isObj {
		sc.addf(name, nil, CodeSchema, "config must be an object")
		return "", nil
	}
	raw, has := obj["manifest"]
	if !has {
		return "", nil
	}
	mp, isStr := raw.(string)
	if !isStr {
		sc.addf(name, []string{"manifest"}, CodeManifestPath, "manifest must be a string")
		return "", nil
	}
	if !plainPath(mp) {
		sc.addf(name, []string{"manifest"}, CodeManifestPath, "manifest %s is not a plain repository-relative path", mp)
		return "", nil
	}
	return mp, nil
}

// decodeConfig decodes a config file strictly, recording a problem and returning false if it is not valid.
func (sc *scan) decodeConfig(name string, data []byte) (any, bool) {
	if name == configYAML {
		doc, yerr := yamlsafe.Decode(data, yamlsafe.Limits{MaxBytes: sc.lim.MaxFileBytes, MaxDepth: sc.lim.MaxDepth, MaxNodes: sc.lim.MaxNodes, Name: "config"})
		if yerr != nil {
			sc.yamlProblem(name, yerr)
			return nil, false
		}
		return doc, true
	}
	doc, perr := parseJSON(data, sc.lim.MaxDepth)
	if perr != nil {
		sc.parseProblem(name, perr)
		return nil, false
	}
	return doc, true
}

// plainPath reports whether p is a valid repository-relative path with no wildcard.
func plainPath(p string) bool {
	return pathglob.ValidatePath(p) == nil && !strings.ContainsAny(p, `*?[\`)
}

// statManifest checks that the explicit manifest is a regular file within the cap, recording a problem if not.
func (sc *scan) statManifest(p string) (fs.FileInfo, bool) {
	info, err := fs.Lstat(sc.tree, p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		sc.addf(p, nil, CodeManifestPath, "manifest file named by the config does not exist")
	case err != nil:
		// A symlink in a directory component is reported by the tree as an error, and is not followed.
		sc.addf(p, nil, CodeUnreadable, "manifest cannot be read: %s", err.Error())
	case info.Mode()&fs.ModeSymlink != 0:
		sc.addf(p, nil, CodeSymlink, "manifest is a symlink")
	case !info.Mode().IsRegular():
		sc.addf(p, nil, CodeSchema, "manifest is not a regular file")
	case info.Size() > int64(sc.lim.MaxFileBytes):
		sc.addf(p, nil, CodeTooLarge, "manifest is larger than %d bytes", sc.lim.MaxFileBytes)
	default:
		return info, true
	}
	return nil, false
}

// manifest reads the explicit manifest, strictly, whether or not it is flag-shaped.
func (sc *scan) manifest(p string) error {
	info, ok := sc.statManifest(p)
	if !ok {
		return nil
	}
	data, err := sc.read(p, info.Size())
	if err != nil {
		return err
	}
	doc, perr := parseJSON(data, sc.lim.MaxDepth)
	if perr != nil {
		sc.parseProblem(p, perr)
		return nil
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		sc.addf(p, nil, CodeSchema, "top level must be an object")
		return nil
	}
	return sc.manifestFlags(p, obj)
}
