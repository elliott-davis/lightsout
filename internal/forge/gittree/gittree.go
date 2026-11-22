// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package gittree is a read-only [fs.FS] over the entries of one git tree.
//
// It never touches the OS file system. Blobs are regular files, symlinks and gitlinks (submodules) are reported
// but never followed, and any path with a symlink in a component is refused with [forge.ErrSymlink], so a
// symlinked policy file cannot be parsed as policy. Names are preserved exactly, case-colliding names included.
//
// Completeness is the adapter's job. [New] cannot tell that its entry list was truncated, so callers must never
// build a tree from a truncated listing: an adapter that could not enumerate every entry returns
// [forge.ErrIncomplete] and does not call New.
package gittree

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// Default limits (design: file size 10 MiB, entry count 200k).
const (
	DefaultMaxFileBytes  = 10 << 20
	DefaultMaxEntries    = 200_000
	DefaultMaxPathBytes  = 64 << 20
	DefaultMaxTotalBytes = 1 << 30
)

// ErrInvalidEntry wraps every [New] validation failure other than the entry-count limit.
var ErrInvalidEntry = errors.New("gittree: invalid entry")

// EntryMode is the git mode of an entry.
type EntryMode int

// Entry modes. The zero value is invalid.
const (
	ModeInvalid    EntryMode = iota
	ModeBlob                 // regular file
	ModeExecutable           // regular file with the executable bit
	ModeSymlink              // Data is the link target
	ModeGitlink              // a submodule commit, SHA is the commit
	ModeTree                 // a directory
)

func (m EntryMode) String() string {
	names := []string{"invalid", "blob", "executable", "symlink", "gitlink", "tree"}
	if m < 0 || int(m) >= len(names) {
		return "invalid"
	}
	return names[m]
}

// FileMode is the [fs.FileMode] the tree reports for the entry mode: 0o644 for a blob, 0o755 for an executable,
// [fs.ModeSymlink], [fs.ModeIrregular] for a gitlink and [fs.ModeDir] for a directory.
func (m EntryMode) FileMode() fs.FileMode {
	switch m {
	case ModeInvalid:
		return 0
	case ModeBlob:
		return 0o644
	case ModeExecutable:
		return 0o755
	case ModeSymlink:
		return fs.ModeSymlink
	case ModeGitlink:
		return fs.ModeIrregular
	case ModeTree:
		return fs.ModeDir | 0o755
	}
	return 0
}

// Entry is one tree entry. Data is the blob bytes or the symlink target, and is not copied by [New].
type Entry struct {
	Path string
	Mode EntryMode
	Data []byte
	SHA  string
}

// Limits bound a tree. A zero field means the default. MaxEntries counts every node, synthesized directories
// included, and MaxPathBytes bounds the total bytes of all node paths, so a few very deep paths cannot blow up
// memory. MaxFileBytes applies to each blob and symlink target, and MaxTotalBytes to all of them together.
type Limits struct {
	MaxFileBytes  int
	MaxEntries    int
	MaxPathBytes  int
	MaxTotalBytes int
}

func (l Limits) withDefaults() Limits {
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultMaxFileBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	if l.MaxPathBytes <= 0 {
		l.MaxPathBytes = DefaultMaxPathBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = DefaultMaxTotalBytes
	}
	return l
}

type node struct {
	name     string
	mode     EntryMode // ModeTree for directories, including synthesized ones
	data     []byte
	sha      string
	explicit bool
	children []string // full paths, sorted by base name
}

// FS is a read-only tree. It implements [fs.FS], [fs.ReadDirFS], [fs.ReadFileFS] and [fs.StatFS], and is safe
// for concurrent use.
type FS struct {
	nodes      map[string]*node
	lim        Limits
	pathBytes  int
	totalBytes int
}

var (
	_ fs.FS         = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	_ fs.ReadLinkFS = (*FS)(nil)
)

// New builds a tree from entries. It validates every path with [fs.ValidPath] and [pathglob.ValidatePath], and
// rejects a duplicate path, a path under a blob, symlink or gitlink, and an invalid mode (each wraps
// [ErrInvalidEntry]), and so does a name with a control character (C0, DEL, C1) or a backslash, so that the tree
// fails closed. A blob or symlink target over lim.MaxFileBytes, or more than lim.MaxTotalBytes of content, is
// [forge.ErrTooLarge] too. Names may contain bidirectional or zero-width characters, and lookups match them
// exactly: consumers must escape paths on output. Too many nodes (entries plus synthesized directories) or too many total path bytes is
// [forge.ErrTooLarge]. Missing intermediate directories are synthesized. A ".git" name is allowed here, so a
// consumer such as contract.Load can detect a nested repository; the factory's own write path refuses it.
func New(entries []Entry, lim Limits) (*FS, error) {
	lim = lim.withDefaults()
	if len(entries) > lim.MaxEntries {
		return nil, fmt.Errorf("gittree: %d entries exceed the limit of %d: %w", len(entries), lim.MaxEntries, forge.ErrTooLarge)
	}
	t := &FS{nodes: map[string]*node{".": {name: ".", mode: ModeTree, explicit: true}}, lim: lim}
	for _, e := range entries {
		if err := t.add(e); err != nil {
			return nil, err
		}
	}

	for p := range t.nodes {
		if p == "." {
			continue
		}
		parent := t.nodes[parentOf(p)]
		parent.children = append(parent.children, p)
	}
	for _, n := range t.nodes {
		slices.SortFunc(n.children, func(a, b string) int { return strings.Compare(path.Base(a), path.Base(b)) })
	}
	return t, nil
}

func parentOf(p string) string {
	d := path.Dir(p)
	return d
}

func invalid(p, why string) error {
	return fmt.Errorf("%w: %q: %s", ErrInvalidEntry, p, why)
}

// badName reports whether a path contains a character no tracked file name should: a C0 or C1 control character,
// DEL, or a backslash.
func badName(p string) bool {
	for _, r := range p {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '\\' {
			return true
		}
	}
	return false
}

// newNode registers a node, counting it against the limits.
func (t *FS) newNode(p string, n *node) error {
	if len(t.nodes) > t.lim.MaxEntries { // the root is not counted
		return fmt.Errorf("gittree: more than %d nodes: %w", t.lim.MaxEntries, forge.ErrTooLarge)
	}
	t.pathBytes += len(p)
	if t.pathBytes > t.lim.MaxPathBytes {
		return fmt.Errorf("gittree: paths exceed %d bytes: %w", t.lim.MaxPathBytes, forge.ErrTooLarge)
	}
	t.nodes[p] = n
	return nil
}

func (t *FS) add(e Entry) error {
	if !fs.ValidPath(e.Path) || e.Path == "." {
		return invalid(e.Path, "not a valid file system path")
	}
	if err := pathglob.ValidatePath(e.Path); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	if badName(e.Path) {
		return invalid(e.Path, "control character or backslash in name")
	}
	if e.Mode <= ModeInvalid || e.Mode > ModeTree {
		return invalid(e.Path, "invalid mode")
	}
	if len(e.Data) > t.lim.MaxFileBytes {
		return fmt.Errorf("gittree: %q has %d bytes, over the limit of %d: %w", e.Path, len(e.Data), t.lim.MaxFileBytes, forge.ErrTooLarge)
	}
	t.totalBytes += len(e.Data)
	if t.totalBytes > t.lim.MaxTotalBytes {
		return fmt.Errorf("gittree: content exceeds %d bytes: %w", t.lim.MaxTotalBytes, forge.ErrTooLarge)
	}
	start := 0
	for i := range len(e.Path) {
		if e.Path[i] != '/' {
			continue
		}
		dir := e.Path[:i]
		n, ok := t.nodes[dir]
		switch {
		case !ok:
			if err := t.newNode(dir, &node{name: e.Path[start:i], mode: ModeTree}); err != nil {
				return err
			}
		case n.mode != ModeTree:
			return invalid(e.Path, "path is under a "+n.mode.String()+" at "+dir)
		}
		start = i + 1
	}
	if n, ok := t.nodes[e.Path]; ok {
		switch {
		case n.explicit:
			return invalid(e.Path, "duplicate path")
		case e.Mode != ModeTree:
			return invalid(e.Path, "path is also a directory")
		}
		n.explicit = true
		n.sha = e.SHA
		return nil
	}
	return t.newNode(e.Path, &node{name: e.Path[start:], mode: e.Mode, data: e.Data, sha: e.SHA, explicit: true})
}

// resolve finds name, refusing a symlink in any directory component. When strict, a symlink or gitlink as the
// final component is refused too.
func (t *FS) resolve(op, name string, strict bool) (*node, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	n := t.nodes["."]
	if name == "." {
		return n, nil
	}
	for end := 0; end < len(name); {
		if n.mode != ModeTree {
			return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		if next := strings.IndexByte(name[end:], '/'); next < 0 {
			end = len(name)
		} else {
			end += next
		}
		child, ok := t.nodes[name[:end]]
		if !ok {
			return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		n = child
		last := end == len(name)
		if !last {
			end++ // skip the slash
		}
		switch {
		case n.mode == ModeSymlink && (!last || strict):
			return nil, &fs.PathError{Op: op, Path: name, Err: forge.ErrSymlink}
		case n.mode == ModeGitlink && (!last || strict):
			return nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("gitlink: %w", forge.ErrUnsupported)}
		}
	}
	return n, nil
}

func (t *FS) tooLarge(op, name string, n *node) error {
	if len(n.data) > t.lim.MaxFileBytes && (n.mode == ModeBlob || n.mode == ModeExecutable) {
		return &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%d bytes exceed the limit of %d: %w", len(n.data), t.lim.MaxFileBytes, forge.ErrTooLarge)}
	}
	return nil
}

// Open implements [fs.FS]. A symlink in any component is [forge.ErrSymlink], and a gitlink cannot be opened.
func (t *FS) Open(name string) (fs.File, error) {
	n, err := t.resolve("open", name, true)
	if err != nil {
		return nil, err
	}
	if n.mode == ModeTree {
		return &dir{t: t, n: n, path: name}, nil
	}
	if err := t.tooLarge("open", name, n); err != nil {
		return nil, err
	}
	return &file{Reader: bytes.NewReader(n.data), info: infoOf(n)}, nil
}

// ReadFile implements [fs.ReadFileFS]. The returned slice is a copy.
func (t *FS) ReadFile(name string) ([]byte, error) {
	n, err := t.resolve("readfile", name, true)
	if err != nil {
		return nil, err
	}
	if n.mode == ModeTree {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: errors.New("is a directory")}
	}
	if err := t.tooLarge("readfile", name, n); err != nil {
		return nil, err
	}
	return bytes.Clone(n.data), nil
}

// Stat implements [fs.StatFS]. It behaves like [FS.Lstat]: a final symlink or gitlink is reported, not followed,
// and a symlink in a directory component is [forge.ErrSymlink].
func (t *FS) Stat(name string) (fs.FileInfo, error) {
	n, err := t.resolve("stat", name, false)
	if err != nil {
		return nil, err
	}
	return infoOf(n), nil
}

// Lstat implements [fs.ReadLinkFS]. It is the same as Stat.
func (t *FS) Lstat(name string) (fs.FileInfo, error) {
	n, err := t.resolve("lstat", name, false)
	if err != nil {
		return nil, err
	}
	return infoOf(n), nil
}

// ReadDir implements [fs.ReadDirFS], in sorted order.
func (t *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	n, err := t.resolve("readdir", name, true)
	if err != nil {
		return nil, err
	}
	if n.mode != ModeTree {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	return t.entries(n, 0, len(n.children)), nil
}

// entries builds the directory entries of n.children[from:to] only.
func (t *FS) entries(n *node, from, to int) []fs.DirEntry {
	out := make([]fs.DirEntry, 0, to-from)
	for _, c := range n.children[from:to] {
		out = append(out, fs.FileInfoToDirEntry(infoOf(t.nodes[c])))
	}
	return out
}

// ReadLink returns the target of the symlink at name. No component, including the last, is followed.
func (t *FS) ReadLink(name string) (string, error) {
	n, err := t.resolve("readlink", name, false)
	if err != nil {
		return "", err
	}
	if n.mode != ModeSymlink {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: errors.New("not a symlink")}
	}
	if len(n.data) > t.lim.MaxFileBytes {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fmt.Errorf("link target of %d bytes: %w", len(n.data), forge.ErrTooLarge)}
	}
	return string(n.data), nil
}

type info struct{ n *node }

func infoOf(n *node) fs.FileInfo { return info{n} }

func (i info) Name() string { return i.n.name }
func (i info) Size() int64 {
	if i.n.mode == ModeTree {
		return 0
	}
	return int64(len(i.n.data))
}
func (i info) Mode() fs.FileMode  { return i.n.mode.FileMode() }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.n.mode == ModeTree }
func (i info) Sys() any           { return nil }

type file struct {
	*bytes.Reader
	info fs.FileInfo
}

func (f *file) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *file) Close() error               { return nil }

type dir struct {
	t    *FS
	n    *node
	path string
	off  int
}

func (d *dir) Stat() (fs.FileInfo, error) { return infoOf(d.n), nil }
func (d *dir) Close() error               { return nil }
func (d *dir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: errors.New("is a directory")}
}

func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	left := len(d.n.children) - d.off
	if n <= 0 {
		out := d.t.entries(d.n, d.off, d.off+left)
		d.off += left
		return out, nil
	}
	if left == 0 {
		return nil, io.EOF
	}
	n = min(n, left)
	out := d.t.entries(d.n, d.off, d.off+n)
	d.off += n
	return out, nil
}
