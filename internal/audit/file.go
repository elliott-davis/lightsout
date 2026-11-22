// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// MaxLineBytes is the longest JSON line the file backend reads or writes.
const MaxLineBytes = 1 << 20

var errLineTooLong = errors.New("line too long")

// File is a JSON Lines [Backend]: one entry per line, appended with a single write and an fsync. Holding a File
// is a write capability: it can append entries with any seal, so only the [Log]'s owner should hold it.
//
// The file is untrusted input. [CreateFile] makes a new file and [OpenFile] opens an existing one.
//
// What the file checks protect: both functions open the final path component without following symlinks, require
// a regular file (checked by fstat on the open descriptor) with a single hard link, owner read and write
// permission, no group or other permissions, and the current user as owner ([ErrInsecureFile]). They check the
// parent directory (opened without following a symlink as its final component): it must be owned by the current
// user and not writable by group or others. They take an exclusive flock, so a second File on the same path
// fails with [ErrLocked]; the lock is taken first and every other check runs while holding it, and the path must
// still name the locked file afterwards. On Linux, a file or directory carrying a POSIX ACL is rejected. On macOS
// and the BSDs neither the file nor the directory is checked for ACLs: an inheritable directory ACL (for example
// "chmod +a 'everyone allow write,file_inherit'") passes straight to a new 0600 file, so the operator must make
// sure the audit directory carries none.
//
// What they do not protect: only the final component of the path is protected from symlinks. A symlink in an
// earlier component is followed, so the path's ancestors must be trusted. The checks are made when the file is
// opened, not continuously, and an attacker who is the same user, or root, can do anything.
//
// OpenFile reads the whole file, requires every line to be in the canonical encoding this package writes (no
// duplicate or case-variant keys, escapes, whitespace, time offsets or CRLF), recomputes every hash, and fails
// closed with [ErrBrokenChain] on any corruption, including a partial last line left by a crash. Repair is an
// operator action outside this API. [File.Read] re-checks each line it returns against the hash seen at open or
// append.
//
// A file that was truncated (to zero bytes, or by dropping its tail) or replaced with another valid chain is
// still a valid chain, and OpenFile accepts it. Like tail truncation, this is detected only by [Log.VerifyAgainst]
// with a [Head] checkpoint kept outside the log's storage. CreateFile refuses to reuse an existing path, so a
// deleted log does not quietly become a new one through the create path, but a truncate has the same effect.
//
// The file backend is supported on Linux, macOS and the BSDs. Elsewhere CreateFile and OpenFile return an error
// wrapping [errors.ErrUnsupported].
//
// If a write or fsync fails, the on-disk tail is unknown, so the File refuses all further appends with
// [ErrStoreFailed].
type File struct {
	mu     sync.Mutex
	f      *os.File
	lines  []lineRef // lines[i] is entry Seq i+1
	size   int64
	head   Head
	failed error
	// syncFile flushes the file. It is a field so tests can inject failures.
	syncFile func() error
	closed   bool
}

type lineRef struct {
	off  int64
	n    int // length without the trailing newline
	hash Hash
}

type fileEntry struct {
	Format          int               `json:"format"`
	Seq             uint64            `json:"seq"`
	Time            time.Time         `json:"time"`
	Actor           fileActor         `json:"actor"`
	TemplateVersion string            `json:"template_version"`
	Subject         fileSubject       `json:"subject"`
	Action          string            `json:"action"`
	Target          string            `json:"target"`
	Outcome         string            `json:"outcome"`
	Decision        *fileDecision     `json:"decision,omitempty"`
	Link            *fileSubject      `json:"link,omitempty"`
	Attrs           map[string]string `json:"attrs,omitempty"`
	PrevHash        Hash              `json:"prev_hash"`
	Hash            Hash              `json:"hash"`
}

type fileActor struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Display string `json:"display,omitempty"`
}

type fileSubject struct {
	Kind string `json:"kind"`
	Repo string `json:"repo,omitempty"`
	ID   string `json:"id"`
}

type fileDecision struct {
	Operation string `json:"operation"`
	Role      string `json:"role"`
	Revision  string `json:"revision"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason,omitempty"`
}

func toFileEntry(e Entry) fileEntry {
	fe := fileEntry{
		Format:          e.Format,
		Seq:             e.Seq,
		Time:            e.Time.UTC(),
		Actor:           fileActor{Kind: string(e.Actor.Kind), ID: e.Actor.ID, Display: e.Actor.Display},
		TemplateVersion: e.TemplateVersion,
		Subject:         fileSubject{Kind: string(e.Subject.Kind), Repo: e.Subject.Repo, ID: e.Subject.ID},
		Action:          string(e.Action),
		Target:          e.Target,
		Outcome:         e.Outcome,
		Attrs:           e.Attrs,
		PrevHash:        e.PrevHash,
		Hash:            e.Hash,
	}
	if d := e.Decision; d != nil {
		fe.Decision = &fileDecision{
			Operation: d.Operation, Role: d.Role, Revision: d.Revision, Verdict: string(d.Verdict), Reason: d.Reason,
		}
	}
	if l := e.Link; l != nil {
		fe.Link = &fileSubject{Kind: string(l.Kind), Repo: l.Repo, ID: l.ID}
	}
	return fe
}

func (fe fileEntry) entry() Entry {
	e := Entry{
		Format: fe.Format,
		Seq:    fe.Seq,
		Time:   fe.Time.UTC(),
		Record: Record{
			Actor:           Actor{Kind: ActorKind(fe.Actor.Kind), ID: fe.Actor.ID, Display: fe.Actor.Display},
			TemplateVersion: fe.TemplateVersion,
			Subject:         Subject{Kind: SubjectKind(fe.Subject.Kind), Repo: fe.Subject.Repo, ID: fe.Subject.ID},
			Action:          Action(fe.Action),
			Target:          fe.Target,
			Outcome:         fe.Outcome,
			Attrs:           fe.Attrs,
		},
		PrevHash: fe.PrevHash,
		Hash:     fe.Hash,
	}
	if d := fe.Decision; d != nil {
		e.Decision = &Decision{
			Operation: d.Operation, Role: d.Role, Revision: d.Revision, Verdict: Verdict(d.Verdict), Reason: d.Reason,
		}
	}
	if l := fe.Link; l != nil {
		e.Link = &Subject{Kind: SubjectKind(l.Kind), Repo: l.Repo, ID: l.ID}
	}
	return cloneEntry(e) // normalizes empty Attrs to nil
}

// decodeLine decodes one line and requires it to be byte-for-byte what [File.AppendNext] would have written for
// the decoded entry. encoding/json is lenient (case-insensitive and duplicate keys, escapes, whitespace, time
// offsets, null), so without this check a line could mean one thing to this package and another to a reader
// such as jq.
func decodeLine(line []byte) (Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var fe fileEntry
	if err := dec.Decode(&fe); err != nil {
		return Entry{}, lineError(decodeReason(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Entry{}, lineError("trailing data after entry")
	}
	e := fe.entry()
	canon, err := json.Marshal(toFileEntry(e))
	if err != nil || !bytes.Equal(canon, line) {
		return Entry{}, lineError("line is not in canonical form")
	}
	return e, nil
}

// lineError is a fixed-text reason a line was rejected. Decoder errors are never embedded: they quote the
// offending (untrusted, possibly huge) value.
type lineError string

func (e lineError) Error() string { return string(e) }

func decodeReason(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	var tm *time.ParseError
	switch {
	case errors.As(err, &syn), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "syntax error"
	case errors.As(err, &typ):
		return "type mismatch"
	case errors.As(err, &tm):
		return "bad time"
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		return "unknown field"
	}
	return "bad value"
}

// CreateFile creates a new audit file at path (O_EXCL, mode 0600, parent directory fsynced) and locks it. It
// fails if path already exists.
func CreateFile(ctx context.Context, path string) (*File, error) {
	return openAudit(ctx, path, true)
}

// OpenFile opens the existing audit file at path, locks it, verifies the whole chain and positions for
// appending. A missing file is an error wrapping fs.ErrNotExist. It fails with a *[ChainError] if the file is
// corrupt.
func OpenFile(ctx context.Context, path string) (*File, error) {
	return openAudit(ctx, path, false)
}

func openAudit(ctx context.Context, path string, create bool) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := openLocked(path, create)
	if err != nil {
		return nil, err
	}
	af := &File{f: f, syncFile: f.Sync}
	if err := af.load(ctx); err != nil {
		if create {
			removeCreated(path, f) // still holding the lock
		}
		_ = f.Close()
		return nil, err
	}
	return af, nil
}

func (a *File) load(ctx context.Context) error {
	r := bufio.NewReaderSize(a.f, 64<<10)
	var off int64
	var prev Head
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, complete, err := readLine(r)
		if errors.Is(err, io.EOF) {
			break
		}
		pos := prev.Seq + 1
		if errors.Is(err, errLineTooLong) {
			return &ChainError{Seq: pos, Reason: fmt.Sprintf("line longer than %d bytes", MaxLineBytes)}
		}
		if err != nil {
			return fmt.Errorf("read audit file: %w", err)
		}
		if !complete {
			return &ChainError{Seq: pos, Reason: "partial last line"}
		}
		e, err := decodeLine(line)
		if err != nil {
			return &ChainError{Seq: pos, Reason: "malformed line: " + err.Error()}
		}
		if err := checkLink(prev, e); err != nil {
			return err
		}
		a.lines = append(a.lines, lineRef{off: off, n: len(line), hash: e.Hash})
		off += int64(len(line)) + 1
		prev = headOf(e)
	}
	a.size = off
	a.head = prev
	return nil
}

// readLine reads one line without its newline. complete is false when the data ended without a newline.
func readLine(r *bufio.Reader) (line []byte, complete bool, err error) {
	var acc []byte
	for {
		chunk, err := r.ReadSlice('\n')
		acc = append(acc, chunk...)
		if len(acc) > MaxLineBytes+1 {
			return nil, false, errLineTooLong
		}
		switch {
		case err == nil:
			acc = acc[:len(acc)-1]
			if len(acc) > MaxLineBytes {
				return nil, false, errLineTooLong
			}
			return acc, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(acc) == 0 {
				return nil, false, io.EOF
			}
			return acc, false, nil
		default:
			return nil, false, err
		}
	}
}

// AppendNext implements [Backend].
func (a *File) AppendNext(ctx context.Context, seal SealFunc) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil { // the context may have ended while waiting for the lock
		return Entry{}, err
	}
	if a.closed {
		return Entry{}, ErrClosed
	}
	if a.failed != nil {
		return Entry{}, fmt.Errorf("%w: %w", ErrStoreFailed, a.failed)
	}
	e, err := seal(a.head)
	if err != nil {
		return Entry{}, err
	}
	if cerr := checkLink(a.head, e); cerr != nil {
		return Entry{}, fmt.Errorf("sealed entry rejected: %w", cerr)
	}
	line, err := json.Marshal(toFileEntry(e))
	if err != nil {
		return Entry{}, fmt.Errorf("encode audit entry: %w", err)
	}
	if len(line) > MaxLineBytes {
		return Entry{}, fmt.Errorf("%w: encoded entry is %d bytes, over %d", ErrInvalidRecord, len(line), MaxLineBytes)
	}
	line = append(line, '\n')
	if _, err := a.f.Write(line); err != nil {
		a.failed = err
		return Entry{}, &StoreError{Seq: e.Seq, Hash: e.Hash, Err: fmt.Errorf("write: %w", err)}
	}
	if err := a.syncFile(); err != nil {
		a.failed = err
		return Entry{}, &StoreError{Seq: e.Seq, Hash: e.Hash, Err: fmt.Errorf("fsync: %w", err)}
	}
	a.lines = append(a.lines, lineRef{off: a.size, n: len(line) - 1, hash: e.Hash})
	a.size += int64(len(line))
	a.head = headOf(e)
	return cloneEntry(e), nil
}

// readBudget caps the bytes one [File.Read] call reads while holding the lock.
const readBudget = 4 << 20

// Read implements [Backend]. It streams entries from the file and re-checks each against the hash recorded at
// open or append. A line that was changed, no longer parses, or is gone because the file shrank is reported as a
// *[ChainError]; any other I/O error is returned wrapped and is not [ErrBrokenChain].
//
// A call reads at most 4 MiB, so it may return fewer than limit entries (but at least one, if any remain)
// before the end of the log. Callers page on from the last returned Seq.
func (a *File) Read(ctx context.Context, fromSeq uint64, limit int) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fromSeq == 0 {
		fromSeq = 1
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrClosed
	}
	out := []Entry{}
	read := 0
	for i := fromSeq - 1; i < uint64(len(a.lines)) && len(out) < limit && (read < readBudget || len(out) == 0); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e, err := a.readEntry(i)
		if err != nil {
			return nil, err
		}
		read += a.lines[i].n + 1
		out = append(out, e)
	}
	return out, nil
}

// readEntry reads and re-verifies the entry at index i. The caller holds a.mu.
func (a *File) readEntry(i uint64) (Entry, error) {
	ref := a.lines[i]
	buf := make([]byte, ref.n+1)
	if _, err := a.f.ReadAt(buf, ref.off); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Entry{}, &ChainError{Seq: i + 1, Reason: "file is shorter than when it was verified"}
		}
		return Entry{}, fmt.Errorf("read audit file: %w", err)
	}
	if buf[ref.n] != '\n' {
		return Entry{}, &ChainError{Seq: i + 1, Reason: "line is not newline-terminated where it was verified"}
	}
	e, err := decodeLine(buf[:ref.n])
	if err != nil {
		return Entry{}, &ChainError{Seq: i + 1, Reason: "malformed line: " + err.Error()}
	}
	if e.Seq != i+1 || e.Hash != ref.hash || computeHash(e) != e.Hash {
		return Entry{}, &ChainError{Seq: i + 1, Reason: "line changed since it was verified"}
	}
	return e, nil
}

// Head implements [Backend].
func (a *File) Head(ctx context.Context) (Head, error) {
	if err := ctx.Err(); err != nil {
		return Head{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return Head{}, ErrClosed
	}
	return a.head, nil
}

// Close closes the file. Later calls on the File return [ErrClosed].
func (a *File) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.f.Close()
}
