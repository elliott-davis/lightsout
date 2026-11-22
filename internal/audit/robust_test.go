// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestFile_HostileLinesGiveBoundedErrors(t *testing.T) { // NFR-4: untrusted bytes are never echoed
	t.Parallel()
	requirePOSIXFiles(t)
	huge := strings.Repeat("9", 900_000)
	forms := map[string]func(line string) string{
		"unknown key": func(l string) string { return `{"` + strings.Repeat("k", 900_000) + `":1,` + l[1:] },
		"huge seq":    func(l string) string { return strings.Replace(l, `"seq":2`, `"seq":`+huge, 1) },
		"huge time": func(l string) string {
			return regexp.MustCompile(`"time":"[^"]*"`).ReplaceAllString(l, `"time":"`+strings.Repeat("x", 900_000)+`"`)
		},
		"huge hash": func(l string) string {
			return regexp.MustCompile(`"hash":"[^"]*"`).ReplaceAllString(l, `"hash":"`+strings.Repeat("a", 900_000)+`"`)
		},
		"wrong type": func(l string) string { return strings.Replace(l, `"seq":2`, `"seq":"`+huge+`"`, 1) },
	}
	check := func(t *testing.T, err error) {
		t.Helper()
		assertChainErrAt(t, err, 2)
		if n := len(err.Error()); n > 300 {
			t.Errorf("error is %d bytes: %.100s...", n, err.Error())
		}
	}
	for name, mutate := range forms {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path, _ := buildFile(t, 3)
			l, _ := reopenFileLog(t, path)
			lines := readLines(t, path)
			lines[1] = mutate(strings.TrimSuffix(lines[1], "\n"))
			writeLines(t, path, lines)
			_, err := l.Read(t.Context(), 1, 10)
			check(t, err)
			_, err = l.Verify(t.Context())
			check(t, err)
		})
		t.Run(name+" at open", func(t *testing.T) {
			t.Parallel()
			path, _ := buildFile(t, 3)
			lines := readLines(t, path)
			lines[1] = mutate(strings.TrimSuffix(lines[1], "\n"))
			writeLines(t, path, lines)
			_, err := OpenFile(t.Context(), path)
			check(t, err)
		})
	}
}

func TestFile_TruncationIsOnlyDetectedByCheckpoint(t *testing.T) { // NFR-4
	t.Parallel()
	requirePOSIXFiles(t)
	path, saved := buildFile(t, 3)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	l, _ := reopenFileLog(t, path) // an empty file is a valid empty log
	h, err := l.Verify(t.Context())
	if err != nil || h != (Head{}) {
		t.Fatalf("Verify on truncated file = %+v, %v", h, err)
	}
	assertChainErrAt(t, l.VerifyAgainst(t.Context(), saved), 3)
}

func TestFile_ShrunkAfterOpen(t *testing.T) { // NFR-4
	t.Parallel()
	requirePOSIXFiles(t)
	t.Run("short read is a chain error", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 3)
		l, _ := reopenFileLog(t, path)
		b, _ := os.ReadFile(path)
		if err := os.WriteFile(path, b[:len(b)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := l.Read(t.Context(), 1, 10)
		var ce *ChainError
		if !errors.As(err, &ce) {
			t.Fatalf("err = %v, want ChainError", err)
		}
	})
	t.Run("other I/O errors are not chain errors", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 2)
		l, f := reopenFileLog(t, path)
		_ = f.f.Close()
		_, err := l.Read(t.Context(), 1, 10)
		if err == nil || errors.Is(err, ErrBrokenChain) {
			t.Errorf("err = %v, want a plain read error", err)
		}
	})
}

func TestFile_ReadBudget(t *testing.T) { // NFR-4: one Read cannot hold the lock for unbounded I/O
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	l, _ := newFileLog(t, path)
	const n = 90
	for i := range n {
		r := agentRec()
		r.Attrs = map[string]string{}
		for j := range 15 {
			r.Attrs[fmt.Sprintf("k%d", j)] = strings.Repeat("x", 4000)
		}
		r.Target = strconv.Itoa(i)
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	first, err := l.Read(t.Context(), 1, MaxReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(first) >= n {
		t.Fatalf("first page has %d of %d entries; the budget did not apply", len(first), n)
	}
	var all []Entry
	for from := uint64(1); ; {
		page, err := l.Read(t.Context(), from, MaxReadLimit)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		from = page[len(page)-1].Seq + 1
	}
	if len(all) != n {
		t.Errorf("paging recovered %d of %d entries", len(all), n)
	}
	if _, err := l.Verify(t.Context()); err != nil {
		t.Error(err)
	}
}

func TestFile_SyncFailureIsAmbiguous(t *testing.T) { // NFR-4
	t.Parallel()
	requirePOSIXFiles(t)
	t.Run("fsync", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(secureDir(t), "audit.jsonl")
		l, f := newFileLog(t, path)
		if _, err := l.Append(t.Context(), agentRec()); err != nil {
			t.Fatal(err)
		}
		cause := errors.New("disk on fire")
		f.syncFile = func() error { return cause }
		_, err := l.Append(t.Context(), agentRec())
		var se *StoreError
		if !errors.As(err, &se) || !errors.Is(err, ErrStoreFailed) || !errors.Is(err, cause) {
			t.Fatalf("err = %v, want StoreError wrapping ErrStoreFailed and the cause", err)
		}
		if se.Seq != 2 || se.Hash == (Hash{}) {
			t.Errorf("StoreError = %+v", se)
		}
		if _, err := l.Append(t.Context(), agentRec()); !errors.Is(err, ErrStoreFailed) {
			t.Errorf("append after failure err = %v, want sticky", err)
		}
		// The write reached the file, so reconciling after reopen finds the entry the error named.
		_ = f.Close()
		l2, _ := reopenFileLog(t, path)
		tail, _ := l2.Read(t.Context(), se.Seq, 1)
		if len(tail) != 1 || tail[0].Hash != se.Hash {
			t.Errorf("tail after reopen = %v, want hash %s", tail, se.Hash)
		}
	})
	t.Run("write", func(t *testing.T) {
		t.Parallel()
		l, f := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
		_ = f.f.Close()
		_, err := l.Append(t.Context(), agentRec())
		var se *StoreError
		if !errors.As(err, &se) || !errors.Is(err, ErrStoreFailed) || se.Seq != 1 {
			t.Errorf("err = %v, want StoreError at seq 1", err)
		}
	})
}

func TestBackends_ContextCheckedAfterLock(t *testing.T) { // NFR-4
	t.Parallel()
	mk := map[string]func(t *testing.T) Backend{
		"memory": func(*testing.T) Backend { return NewMemory() },
		"file": func(t *testing.T) Backend {
			t.Helper()
			_, f := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
			return f
		},
	}
	for name, newBackend := range mk {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := newBackend(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				// Holds the backend's lock until released.
				_, err := b.AppendNext(t.Context(), func(prev Head) (Entry, error) {
					close(entered)
					<-release
					return sealTest(prev), nil
				})
				if err != nil {
					t.Error(err)
				}
			})
			<-entered
			ctx, cancel := context.WithCancel(t.Context())
			var got error
			sealed := false
			wg.Go(func() {
				_, got = b.AppendNext(ctx, func(prev Head) (Entry, error) {
					sealed = true
					return sealTest(prev), nil
				})
			})
			// Whether the second append is already waiting on the lock or has not started, a cancelled context
			// must stop it before it seals.
			cancel()
			close(release)
			wg.Wait()
			if !errors.Is(got, context.Canceled) || sealed {
				t.Errorf("err = %v, sealed = %v; want Canceled and no seal", got, sealed)
			}
			if h, _ := b.Head(t.Context()); h.Seq != 1 {
				t.Errorf("head seq = %d, want 1", h.Seq)
			}
		})
	}
}

// sealTest builds a valid next entry, the way a Log would.
func sealTest(prev Head) Entry {
	e := Entry{Format: FormatVersion, Seq: prev.Seq + 1, Time: t0.Truncate(time.Microsecond), Record: agentRec(), PrevHash: prev.Hash}
	e.Hash = computeHash(e)
	return e
}

// allFieldsEntry returns an entry with every leaf field set to a non-zero value.
func allFieldsEntry() Entry {
	e := Entry{
		Format: FormatVersion,
		Seq:    7,
		Time:   time.UnixMicro(1772600767123456).UTC(),
		Record: Record{
			Actor:           Actor{Kind: ActorExternal, ID: "id", Display: "disp"},
			TemplateVersion: "tpl",
			Subject:         Subject{Kind: SubjectChange, Repo: "repo", ID: "sid"},
			Action:          ActionDecision,
			Target:          "target",
			Outcome:         "granted",
			Decision:        &Decision{Operation: "op", Role: "role", Revision: "rev", Verdict: VerdictGranted, Reason: "why"},
			Link:            &Subject{Kind: SubjectIssue, Repo: "repo", ID: "iid"},
			Attrs:           map[string]string{"k": "v"},
		},
		PrevHash: Hash{1, 2, 3},
	}
	e.Hash = computeHash(e)
	return e
}

var (
	timeType = reflect.TypeFor[time.Time]()
	hashType = reflect.TypeFor[Hash]()
	attrType = reflect.TypeFor[map[string]string]()
)

// leafPaths lists the field paths of every leaf of v other than the top-level Hash, failing on any kind it does
// not know how to mutate, so a new kind of field forces this test to be extended.
func leafPaths(t *testing.T, typ reflect.Type, prefix []int, out *[][]int) {
	t.Helper()
	for i := range typ.NumField() {
		f := typ.Field(i)
		path := append(slicesClone(prefix), i)
		if len(prefix) == 0 && f.Name == "Hash" {
			continue // the result, not an input
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		case ft == timeType, ft == hashType, ft == attrType:
			*out = append(*out, path)
		case ft.Kind() == reflect.Struct:
			leafPaths(t, ft, path, out)
		case ft.Kind() == reflect.String, ft.Kind() == reflect.Int, ft.Kind() == reflect.Uint64:
			*out = append(*out, path)
		default:
			t.Fatalf("field %s has unsupported kind %s: teach this test how to mutate it", f.Name, ft)
		}
	}
}

func slicesClone(s []int) []int { return append([]int(nil), s...) }

func asTime(v reflect.Value) time.Time {
	t, _ := v.Interface().(time.Time)
	return t
}

func mutateLeaf(v reflect.Value) {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	switch {
	case v.Type() == timeType:
		v.Set(reflect.ValueOf(asTime(v).Add(time.Microsecond)))
	case v.Type() == hashType:
		h, _ := v.Interface().(Hash)
		h[31] ^= 1
		v.Set(reflect.ValueOf(h))
	case v.Type() == attrType:
		m := map[string]string{"extra": "x"}
		old, _ := v.Interface().(map[string]string)
		for k, val := range old {
			m[k] = val
		}
		v.Set(reflect.ValueOf(m))
	case v.Kind() == reflect.String:
		v.SetString(v.String() + "x")
	case v.Kind() == reflect.Int:
		v.SetInt(v.Int() + 1)
	case v.Kind() == reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	}
}

func TestHash_CoversEveryField(t *testing.T) { // NFR-4, SEC-10 data: a future field cannot be forgotten
	t.Parallel()
	base := allFieldsEntry()
	var paths [][]int
	leafPaths(t, reflect.TypeFor[Entry](), nil, &paths)
	if len(paths) < 20 {
		t.Fatalf("only %d leaf fields found", len(paths))
	}
	want := computeHash(base)
	for _, p := range paths {
		e := cloneEntry(base)
		v := reflect.ValueOf(&e).Elem().FieldByIndex(p)
		if v.IsZero() {
			t.Errorf("field %v is zero in the base entry: set it in allFieldsEntry", p)
			continue
		}
		mutateLeaf(v)
		if computeHash(e) == want {
			t.Errorf("changing field %s did not change the hash", reflect.TypeFor[Entry]().FieldByIndex(p[:1]).Name+fmt.Sprint(p))
		}
	}
}

func TestFileEncoding_RoundTripsEveryField(t *testing.T) { // NFR-4
	t.Parallel()
	base := allFieldsEntry()
	line, err := jsonLine(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(base, got); diff != "" {
		t.Errorf("encode/decode round trip lost data (-want +got):\n%s", diff)
	}
}
