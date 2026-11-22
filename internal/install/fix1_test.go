// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/codeowners"
	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/install"
	"github.com/elliott-davis/lightsout/internal/install/installtest"
)

func TestParse_ProtectedMustCoverTheDefaults(t *testing.T) { // CON-5, CON-2, SEC-2
	t.Parallel()
	valid := validYAML(t)
	const fixtureList = `  protected:
    - ".github/workflows/**"
    - ".github/actions/**"
    - ".github/CODEOWNERS"
    - "CODEOWNERS"
    - "docs/CODEOWNERS"
`
	defaults := install.DefaultProtected()
	if len(defaults) != 2+len(codeowners.Locations()) {
		t.Fatalf("DefaultProtected = %v", defaults)
	}
	for _, missing := range defaults {
		t.Run("missing "+missing, func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			b.WriteString("  protected:\n")
			for _, p := range defaults {
				if p != missing {
					fmt.Fprintf(&b, "    - %q\n", p)
				}
			}
			wantProblem(t, replaceOnce(t, valid, fixtureList, b.String()), install.CodeInvalid, "/baseline/protected")
		})
	}
	// A covering list is accepted: directories above, and the whole tree.
	mustParse(t, replaceOnce(t, valid, fixtureList, "  protected: [\".github/**\", \"CODEOWNERS\", \"docs/CODEOWNERS\"]\n"))
	mustParse(t, replaceOnce(t, valid, fixtureList, "  protected: [\"**\"]\n"))
}

func TestActivationRevision(t *testing.T) { // RUN-1, SEC-10
	t.Parallel()
	rev := func(id string, gen uint64, cand string) string {
		t.Helper()
		v, err := install.ActivationRevision(id, gen, cand)
		if err != nil {
			t.Fatalf("ActivationRevision(%q, %d, %q): %v", id, gen, cand, err)
		}
		return v
	}
	cand := strings.Repeat("a", 40)
	got := rev("inst-1", 7, cand)
	if len(got) != 64 || strings.Trim(got, "0123456789abcdef") != "" {
		t.Fatalf("ActivationRevision = %q, want 64 lowercase hex digits", got)
	}
	// The documented layout, written out byte by byte: the domain, then each field as a u64 length and its bytes.
	var want bytes.Buffer
	want.WriteString("lightsout/install-activation/v1\n")
	u64 := func(n uint64) { _ = binary.Write(&want, binary.BigEndian, n) }
	u64(6)
	want.WriteString("inst-1")
	u64(8)
	u64(7)
	u64(40)
	want.WriteString(cand)
	sum := sha256.Sum256(want.Bytes())
	if golden := hex.EncodeToString(sum[:]); got != golden {
		t.Errorf("ActivationRevision = %s, want %s from the written-out bytes", got, golden)
	}
	const pinned = "1b99f89d85aac7ca349d32eb1f05616638a2fcc3fb45f0f162af16595e41293a"
	if got != pinned {
		t.Errorf("ActivationRevision = %s, want %s: the encoding is a signed-over format", got, pinned)
	}
	others := map[string]string{
		"generation":       rev("inst-1", 8, cand),
		"previous":         rev("inst-1", 6, cand),
		"candidate":        rev("inst-1", 7, strings.Repeat("b", 40)),
		"candidate length": rev("inst-1", 7, strings.Repeat("a", 64)),
		"install":          rev("inst-2", 7, cand),
	}
	for name, v := range others {
		if v == got {
			t.Errorf("changing the %s does not change the activation revision", name)
		}
	}
	if rev("inst-1", 7, cand) != got {
		t.Error("not deterministic")
	}
	if rev("a", 1, strings.Repeat("c", 40)) == rev("a/", 1, strings.Repeat("c", 40)) {
		t.Error("install IDs collide")
	}
}

func TestActivationRevision_RejectsBadInputs(t *testing.T) { // RUN-1, SEC-10
	t.Parallel()
	good := strings.Repeat("a", 40)
	tests := map[string]struct{ id, cand string }{
		"empty install ID":     {"", good},
		"install ID with NUL":  {"inst\x001", good},
		"install ID with LF":   {"inst-1\n", good},
		"install ID leading -": {"-inst", good},
		"install ID too long":  {strings.Repeat("i", 129), good},
		"install ID space":     {"inst 1", good},
		"empty candidate":      {"inst-1", ""},
		"short candidate":      {"inst-1", "abc123"},
		"branch candidate":     {"inst-1", "main"},
		"uppercase candidate":  {"inst-1", strings.ToUpper(good)},
		"candidate 41 hex":     {"inst-1", good + "a"},
		"candidate with LF":    {"inst-1", good + "\n"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if v, err := install.ActivationRevision(tt.id, 1, tt.cand); err == nil {
				t.Errorf("accepted: %s", v)
			}
		})
	}
	if _, err := install.ActivationRevision("inst-1", 0, strings.Repeat("a", 64)); err != nil {
		t.Errorf("generation 0 and a 64-hex candidate: %v", err)
	}
}

type treeReader struct {
	tree fs.FS
	err  error
}

func (r treeReader) Tree(context.Context, forge.RepoID, string) (fs.FS, error) { return r.tree, r.err }

// noLinkFS hides the ReadLinkFS of the tree it wraps.
type noLinkFS struct{ fs.FS }

func TestLoad(t *testing.T) { // RUN-1, SEC-1
	t.Parallel()
	sha := strings.Repeat("c", 40)
	doc := validYAML(t)
	good := fstest.MapFS{"config/install.yaml": {Data: []byte(doc), Mode: 0o644}}

	cfg, err := install.Load(t.Context(), treeReader{tree: good}, "repo-1", sha, "config/install.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := cfg.Baseline()
	if err != nil || cfg.Revision() != sha || b.InstallRevision != sha {
		t.Errorf("Load: revision %q, baseline revision %q, %v, want %q", cfg.Revision(), b.InstallRevision, err, sha)
	}
	if _, err := install.Load(t.Context(), treeReader{tree: good}, "repo-1", strings.Repeat("c", 64), "config/install.yaml"); err != nil {
		t.Errorf("a 64-hex SHA: %v", err)
	}

	tests := map[string]struct {
		r    treeReader
		sha  string
		path string
		want error
	}{
		"short sha":           {treeReader{tree: good}, "abc123", "config/install.yaml", forge.ErrInvalid},
		"branch name":         {treeReader{tree: good}, "main", "config/install.yaml", forge.ErrInvalid},
		"uppercase sha":       {treeReader{tree: good}, strings.ToUpper(sha), "config/install.yaml", forge.ErrInvalid},
		"symlinked file":      {treeReader{tree: fstest.MapFS{"config/install.yaml": {Data: []byte("../real.yaml"), Mode: fs.ModeSymlink}, "real.yaml": {Data: []byte(doc)}}}, sha, "config/install.yaml", forge.ErrSymlink},
		"symlinked directory": {treeReader{tree: fstest.MapFS{"config": {Data: []byte("elsewhere"), Mode: fs.ModeSymlink}, "elsewhere/install.yaml": {Data: []byte(doc)}}}, sha, "config/install.yaml", forge.ErrSymlink},
		"a directory":         {treeReader{tree: fstest.MapFS{"config/install.yaml/x": {Data: []byte(doc)}}}, sha, "config/install.yaml", forge.ErrInvalid},
		"missing":             {treeReader{tree: fstest.MapFS{}}, sha, "config/install.yaml", fs.ErrNotExist},
		"tree without lstat":  {treeReader{tree: noLinkFS{good}}, sha, "config/install.yaml", forge.ErrUnsupported},
		"forge error":         {treeReader{err: forge.ErrNotFound}, sha, "config/install.yaml", forge.ErrNotFound},
		"path escapes":        {treeReader{tree: good}, sha, "../install.yaml", nil},
		"too large":           {treeReader{tree: fstest.MapFS{"i.yaml": {Data: make([]byte, install.MaxFileSize+1)}}}, sha, "i.yaml", forge.ErrTooLarge},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg, err := install.Load(t.Context(), tt.r, "repo-1", tt.sha, tt.path)
			if err == nil || cfg != nil {
				t.Fatalf("Load = %v, %v, want an error", cfg, err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want it to wrap %v", err, tt.want)
			}
		})
	}
	t.Run("invalid content", func(t *testing.T) {
		t.Parallel()
		tree := fstest.MapFS{"i.yaml": {Data: []byte("kind: Install\n")}}
		_, err := install.Load(t.Context(), treeReader{tree: tree}, "repo-1", sha, "i.yaml")
		var ve *install.ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("error = %v, want a *ValidationError", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := install.Load(ctx, treeReader{tree: good}, "repo-1", sha, "config/install.yaml"); err == nil {
			t.Error("a cancelled context loaded")
		}
	})
}

func TestBaseline_NeedsARevision(t *testing.T) { // RUN-1
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	if _, err := cfg.Baseline(); !errors.Is(err, install.ErrNoRevision) {
		t.Errorf("Baseline() = %v, want ErrNoRevision", err)
	}
	withRev, err := cfg.WithRevision(strings.Repeat("e", 40))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withRev.Baseline(); err != nil {
		t.Errorf("Baseline() with a revision: %v", err)
	}
}

func TestRoles_PermissionVocabulary(t *testing.T) { // SEC-2, SEC-3
	t.Parallel()
	valid := validYAML(t)
	coderPerms := `permissions: ["repo:read", "branch:push-own"]`
	for _, perm := range []string{"repo:merge", "branch:push-any", "branch:push-main", "branch:push-protected", "repo:write", "repo:*", "admin:all", "pulls:merge", "workflows:write"} {
		t.Run(perm, func(t *testing.T) {
			t.Parallel()
			doc := replaceOnce(t, valid, coderPerms, `permissions: ["repo:read", "`+perm+`"]`)
			wantProblem(t, doc, install.CodeSchema, "/roles/coder/profile/tools/0/permissions/1")
		})
	}
	// A plain coder: every permission but pulls:review, with push.
	mustParse(t, replaceOnce(t, valid, coderPerms, `permissions: ["repo:read", "issues:read", "issues:comment", "pulls:read", "checks:read", "branch:push-own"]`))
	// A reader may hold every read and review permission.
	mustParse(t, replaceOnce(t, valid, `permissions: ["repo:read", "pulls:review"]`, `permissions: ["repo:read", "issues:read", "issues:comment", "pulls:read", "pulls:review", "checks:read"]`))

	// No reviewer can push (SEC-3): the two core reviewers...
	prTools := `{ name: git, version: "2.47.0", permissions: ["repo:read"] }`
	if strings.Count(valid, prTools) != 2 {
		t.Fatalf("fixture changed: %d reviewer tool lines", strings.Count(valid, prTools))
	}
	push := `{ name: git, version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }`
	first := strings.Replace(valid, prTools, push, 1) // pr-reviewer is the first role with this line
	wantProblem(t, first, install.CodeUnsafeRole, "/roles/pr-reviewer/profile/tools/0/permissions/1")
	second := strings.Replace(valid, prTools, push, 2)
	wantProblem(t, second, install.CodeUnsafeRole, "/roles/security-reviewer/profile/tools/0/permissions/1")
	// ...and every known agent, which is a specialist review (AGD-3).
	specialist := replaceOnce(t, valid, `permissions: ["repo:read", "pulls:review"]`, `permissions: ["repo:read", "branch:push-own"]`)
	wantProblem(t, specialist, install.CodeUnsafeRole, "/roles/payments-specialist/profile/tools/0/permissions/1")
	// A role that is no reviewer may push (the coder does), but it may not also approve (SEC-2).
	both := replaceOnce(t, valid, coderPerms, `permissions: ["repo:read", "pulls:review", "branch:push-own"]`)
	wantProblem(t, both, install.CodeUnsafeRole, "/roles/coder/profile/tools/0/permissions/1")
	// The two permissions may be on different tools of one role: it is the role that must not hold both.
	split := replaceOnce(t, valid, `{ name: go, version: "1.27", permissions: ["repo:read"] }`, `{ name: go, version: "1.27", permissions: ["pulls:review"] }`)
	wantProblem(t, split, install.CodeUnsafeRole, "/roles/coder/profile/tools/1/permissions/0")
}

func TestRoles_FloatingVersionsRejected(t *testing.T) { // RUN-6, AGT-7
	t.Parallel()
	valid := validYAML(t)
	floating := []string{"latest", "stable", "default", "current", "preview", "main", "master", "head", "edge", "nightly", "Latest", "NIGHTLY", "Main", "x"}
	targets := map[string]struct{ old, field string }{
		"model revision":  {`model: { name: "model-a", revision: "2026-10-01" }`, "/roles/coder/profile/model/revision"},
		"harness version": {`harness: { name: claude-code, version: "2.1.0"`, "/roles/coder/profile/harness/version"},
		"tool version":    {`{ name: git, version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }`, "/roles/coder/profile/tools/0/version"},
	}
	for _, f := range floating {
		for name, tg := range targets {
			t.Run(name+" "+f, func(t *testing.T) {
				t.Parallel()
				var repl string
				switch name {
				case "model revision":
					repl = `model: { name: "model-a", revision: "` + f + `" }`
				case "harness version":
					repl = `harness: { name: claude-code, version: "` + f + `"`
				default:
					repl = `{ name: git, version: "` + f + `", permissions: ["repo:read", "branch:push-own"] }`
				}
				doc := strings.Replace(valid, tg.old, repl, 1)
				wantProblem(t, doc, install.CodeInvalid, tg.field)
			})
		}
	}
}

func TestRoles_FloatingVersionsByToken(t *testing.T) { // RUN-6, AGT-7
	t.Parallel()
	valid := validYAML(t)
	bad := []string{
		"claude-3-5-sonnet-latest", "gpt-4o-latest", "llama3:latest", "refs/heads/main", "origin/main", "latest-stable", "canary",
		"lts", "snapshot", "next", "beta", "rolling", "1.x", "v1", "2", "2.x", "latest-1", "2.47-latest", "stable-2",
		"tip", "release", "dev", "2.47.dev", "V3", "1.*", "Foo_LATEST", "a@main",
		// Round 3.
		"refs/heads/develop", "origin/develop", "refs/tags/v1.2.3", "trunk", "develop", "unstable", "experimental",
		"alpha", "rc", "2.0-rc", "x.y.heads.z",
	}
	// Bare majors are floating versions, but they are fine model revisions (0613, 1106, 002, 20250929).
	bareMajors := []string{"v1", "2", "V3"}
	good := []string{
		"claude-sonnet-4-5-20250929", "2.47.0", "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4", "2026-10-01", "1.27", "v2.1.0",
		// Pre-release names followed by a number or a date pin a build.
		"2.0.0-beta.1", "15.0.0-canary.12", "3.0.0-dev.20251001", "o1-preview-2024-09-12", "gemini-2.5-pro-preview-06-05",
	}
	const (
		model   = `model: { name: "model-a", revision: "2026-10-01" }`
		harness = `harness: { name: claude-code, version: "2.1.0"`
		tool    = `{ name: git, version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }`
	)
	build := func(v string) map[string]string {
		return map[string]string{
			"/roles/coder/profile/model/revision":  strings.Replace(valid, model, `model: { name: "model-a", revision: "`+v+`" }`, 1),
			"/roles/coder/profile/harness/version": strings.Replace(valid, harness, `harness: { name: claude-code, version: "`+v+`"`, 1),
			"/roles/coder/profile/tools/0/version": strings.Replace(valid, tool, `{ name: git, version: "`+v+`", permissions: ["repo:read", "branch:push-own"] }`, 1),
		}
	}
	for _, v := range bad {
		for field, doc := range build(v) {
			if field == "/roles/coder/profile/model/revision" && slices.Contains(bareMajors, v) {
				continue
			}
			t.Run(v+" "+field, func(t *testing.T) {
				t.Parallel()
				ps := problemsOf(t, doc)
				// Values the schema's own pattern rejects (the star) fail there; the rest fail as floating.
				if !has(ps, install.CodeInvalid, field) && !has(ps, install.CodeSchema, field) {
					t.Errorf("%q accepted at %s: problems = %v", v, field, ps)
				}
			})
		}
	}
	for _, v := range good {
		for field, doc := range build(v) {
			if _, err := install.Parse([]byte(doc)); err != nil {
				t.Errorf("%q rejected at %s: %v", v, field, err)
			}
		}
	}
}

func TestRoles_ModelRevisionsAndNames(t *testing.T) { // RUN-6, AGT-7
	t.Parallel()
	valid := validYAML(t)
	const model = `model: { name: "model-a", revision: "2026-10-01" }`
	for _, v := range []string{"v1", "2", "V3"} {
		doc := strings.Replace(valid, model, `model: { name: "model-a", revision: "`+v+`" }`, 1)
		if _, err := install.Parse([]byte(doc)); err != nil {
			t.Errorf("model revision %q rejected: %v", v, err)
		}
	}
	for _, rev := range []string{"0613", "1106", "002", "20250929"} {
		doc := strings.Replace(valid, model, `model: { name: "model-a", revision: "`+rev+`" }`, 1)
		if _, err := install.Parse([]byte(doc)); err != nil {
			t.Errorf("model revision %q rejected: %v", rev, err)
		}
	}
	// The model name is checked too, without the bare-major rule.
	for _, name := range []string{"chatgpt-4o-latest", "gpt-latest", "model-a-lts", "refs/heads/main", "origin/model"} {
		doc := strings.Replace(valid, model, `model: { name: "`+name+`", revision: "2026-10-01" }`, 1)
		ps := problemsOf(t, doc)
		if !has(ps, install.CodeInvalid, "/roles/coder/profile/model/name") && !has(ps, install.CodeSchema, "/roles/coder/profile/model/name") {
			t.Errorf("model name %q accepted: %v", name, ps)
		}
	}
	for _, name := range []string{"gpt-4o", "claude-sonnet-4-5", "o1-preview-2024-09-12", "2"} {
		doc := strings.Replace(valid, model, `model: { name: "`+name+`", revision: "2026-10-01" }`, 1)
		if _, err := install.Parse([]byte(doc)); err != nil {
			t.Errorf("model name %q rejected: %v", name, err)
		}
	}
}

func TestRoles_NoForgeCredentials(t *testing.T) { // SEC-2, SEC-3
	t.Parallel()
	valid := validYAML(t)
	prBlock := func(hosts, creds string) string {
		// The pr-reviewer's egress and credential lines; the first role with an egress and a credential after coder.
		i := strings.Index(valid, "  pr-reviewer:\n")
		j := strings.Index(valid, "  security-reviewer:\n")
		block := valid[i:j]
		block = strings.Replace(block, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: [`+hosts+`] }`, 1)
		const modelCred = "    gatewayCredentials:\n      - { name: model-key, host: \"models.internal:443\", operations: [\"POST /v1/messages\"] }\n"
		if !strings.Contains(block, modelCred) {
			t.Fatal("fixture changed: the pr-reviewer has no model credential")
		}
		block = strings.Replace(block, modelCred, creds, 1)
		return strings.Replace(valid, valid[i:j], block, 1)
	}
	tests := map[string]struct {
		doc   string
		field string
	}{
		"reviewer git-receive-pack": {prBlock(`"models.internal:443", "github.com:443"`, "    gatewayCredentials:\n      - { name: model-key, host: \"models.internal:443\", operations: [\"POST /v1/messages\"] }\n      - { name: push, host: \"github.com:443\", operations: [\"POST /o/r.git/git-receive-pack\"] }\n"), "/roles/pr-reviewer/gatewayCredentials/1/host"},
		"reviewer merge":            {prBlock(`"models.internal:443", "api.github.com:443"`, "    gatewayCredentials:\n      - { name: merge, host: \"api.github.com:443\", operations: [\"PUT /repos/o/r/pulls/1/merge\"] }\n"), "/roles/pr-reviewer/gatewayCredentials/0/host"},
		"reviewer graphql":          {prBlock(`"models.internal:443", "api.github.com:443"`, "    gatewayCredentials:\n      - { name: gql, host: \"api.github.com:443\", operations: [\"POST /graphql\"] }\n"), "/roles/pr-reviewer/gatewayCredentials/0/host"},
		"reviewer egress only":      {prBlock(`"models.internal:443", "raw.githubusercontent.com:443"`, ""), "/roles/pr-reviewer/egress/hosts/1"},
	}
	for _, h := range []string{"github.com", "api.github.com", "uploads.github.com", "codeload.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"} {
		doc := strings.Replace(valid, `egress: { hosts: ["models.internal:443"] }
    gatewayCredentials:
      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }
    sandboxSecrets: []`, `egress: { hosts: ["models.internal:443", "`+h+`:443"] }
    gatewayCredentials:
      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }
      - { name: refs, host: "`+h+`:443", operations: ["PATCH /repos/o/r/git/refs/heads/x"] }
    sandboxSecrets: []`, 1)
		tests["coder refs credential, "+h] = struct{ doc, field string }{doc, "/roles/coder/gatewayCredentials/1/host"}
	}
	tests["coder reviews credential"] = struct{ doc, field string }{
		strings.Replace(valid, `egress: { hosts: ["models.internal:443"] }
    gatewayCredentials:
      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }
    sandboxSecrets: []`, `egress: { hosts: ["models.internal:443", "api.github.com:8443"] }
    gatewayCredentials:
      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }
      - { name: review, host: "api.github.com:8443", operations: ["POST /repos/o/r/pulls/1/reviews"] }
    sandboxSecrets: []`, 1),
		"/roles/coder/gatewayCredentials/1/host",
	}
	// A self-hosted forge is named in installation.forgeHosts.
	ghes := replaceOnce(t, valid, `installation: { id: "inst-1", forge: github }`, `installation: { id: "inst-1", forge: github, forgeHosts: ["git.corp.example:443"] }`)
	ghesCoder := strings.Replace(ghes, `egress: { hosts: ["models.internal:443"] }
    gatewayCredentials:
      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }
    sandboxSecrets: []`, `egress: { hosts: ["models.internal:443", "git.corp.example:8443"] }
    gatewayCredentials:
      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }
      - { name: git, host: "git.corp.example:8443", operations: ["POST /api/v3/repos/o/r/git/refs"] }
    sandboxSecrets: []`, 1)
	tests["GHES forgeHosts, egress"] = struct{ doc, field string }{ghesCoder, "/roles/coder/egress/hosts/1"}
	tests["GHES forgeHosts, credential"] = struct{ doc, field string }{ghesCoder, "/roles/coder/gatewayCredentials/1/host"}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, tt.doc, install.CodeUnsafeRole, tt.field)
		})
	}
	// A reviewer whose only credential is the model one passes, and so does a GHES host that is not listed as the forge.
	mustParse(t, valid)
	other := strings.Replace(ghesCoder, `forgeHosts: ["git.corp.example:443"]`, `forgeHosts: ["elsewhere.example:443"]`, 1)
	mustParse(t, other)
}

func TestParse_WeakQualifierKeysRejected(t *testing.T) { // NFR-2, SEC-11
	t.Parallel()
	valid := validYAML(t)
	fixtureKey := qualifier().PublicKey()
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	zeros := make([]byte, 32)
	identity := append([]byte{1}, make([]byte, 31)...)
	withLast := func(b []byte, last byte) []byte { c := slices.Clone(b); c[31] = last; return c }
	pm1 := slices.Repeat([]byte{0xff}, 32)
	pm1[0], pm1[31] = 0xec, 0x7f
	keys := map[string]string{
		"all zeros":                   enc(zeros),
		"all zeros, written out":      strings.Repeat("A", 43) + "=",
		"identity point":              enc(identity),
		"identity point, written out": "AQ" + strings.Repeat("A", 41) + "=",
		"zeros with the sign bit":     enc(withLast(zeros, 0x80)),
		"identity with the sign bit":  enc(withLast(identity, 0x80)),
		"order 2 (p-1)":               enc(pm1),
		"non-canonical y = p":         enc(append([]byte{0xed}, append(slices.Repeat([]byte{0xff}, 30), 0x7f)...)),
		"non-canonical y = p+1":       enc(append([]byte{0xee}, append(slices.Repeat([]byte{0xff}, 30), 0x7f)...)),
		"order 8":                     "JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AU=",
		"order 8, other":              "xxdqcD1N2E+6PAt2DRBnDyogU/osOczGTsf9d5KsA3o=",
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(key) != 44 {
				t.Fatalf("test key %q is not 44 characters", key)
			}
			wantProblem(t, strings.Replace(valid, fixtureKey, key, 1), install.CodeInvalid, "/qualifierKeys/0/key")
		})
	}
	// A real key is still accepted, and so is a different real key.
	other := installtest.NewSigner("q1", "someone else").PublicKey()
	mustParse(t, strings.Replace(valid, fixtureKey, other, 1))
}

func TestParse_StrictBase64(t *testing.T) { // NFR-2
	t.Parallel()
	valid := validYAML(t)
	// A base64 string whose spare bits are not zero decodes to the same bytes under a loose decoder, so two spellings
	// would name one key. Only the canonical one is accepted.
	canon := qualifier().PublicKey()
	variant := nonCanonical(t, canon)
	wantProblem(t, strings.Replace(valid, canon, variant, 1), install.CodeInvalid, "/qualifierKeys/0/key")

	cfg := mustParse(t, valid)
	coder, _ := cfg.Role("coder")
	rec := qualifier().Record(coder.TupleDigest(), install.ResultPass)
	rec.Signature = nonCanonical(t, rec.Signature)
	data, _ := installtest.Encode(rec)
	wantDenied(t, admitRecord(t, valid, data), install.ReasonBadSignature)
}

// nonCanonical returns another spelling of the base64 string s that a loose decoder reads as the same bytes.
func nonCanonical(t *testing.T, s string) string {
	t.Helper()
	want, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.IndexByte(s, '=')
	if i < 0 {
		i = len(s)
	}
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		v := s[:i-1] + string(c) + s[i:]
		if v == s {
			continue
		}
		if got, err := base64.StdEncoding.DecodeString(v); err == nil && slices.Equal(got, want) {
			if _, err := base64.StdEncoding.Strict().DecodeString(v); err == nil {
				t.Fatalf("%q is canonical", v)
			}
			return v
		}
	}
	t.Fatalf("no non-canonical spelling of %q", s)
	return ""
}

func TestParse_DuplicateQualifierKeyID(t *testing.T) { // NFR-2
	t.Parallel()
	other := installtest.NewSigner("q1", "second").PublicKey()
	doc := replaceOnce(t, validYAML(t), "  - { id: q1, key: \"", "  - { id: q1, key: \""+other+"\" }\n  - { id: q1, key: \"")
	wantProblem(t, doc, install.CodeDuplicate, "/qualifierKeys/1/id")
}

func TestParse_EgressHostsRejected(t *testing.T) { // SEC-1, RUN-4
	t.Parallel()
	valid := validYAML(t)
	const egress = `egress: { hosts: ["models.internal:443"] }
    gatewayCredentials:`
	bad := []string{
		"127.0.0.1:80", "127.255.255.254:80", "169.254.169.254:80", "169.254.0.1:80", "0.0.0.0:80",
		"localhost:80", "api.localhost:80", "metadata.google.internal:80", "metadata:80",
		// Spellings that other parsers read as 127.0.0.1 or 169.254.169.254.
		"127.1:80", "127.0.1:80", "2130706433:80", "0x7f.0.0.1:80", "0x7f000001:80", "0177.0.0.1:80", "017700000001:80",
		"127.000.000.001:80", "0251.0376.0251.0376:80", "2852039166:80", "0xa9fea9fe:80", "1.2.3:80", "10.1:80",
		// Round 2.
		"0.1.2.3:80", "0.255.255.255:80", "224.0.0.1:80", "239.255.255.255:80", "255.255.255.255:80",
		"100.100.100.200:80", "168.63.129.16:80", "localhost.localdomain:80", "localhost4:80", "localhost6:80",
		"ip6-localhost:80", "ip6-loopback:80", "instance-data:80", "instance-data.ec2.internal:80", "metadata.goog:80",
		"kubernetes:80", "kubernetes.default:80", "kubernetes.default.svc:80", "foo.svc.cluster.local:80",
		"a.b.svc.cluster.local:80", "host.docker.internal:80", "gateway.docker.internal:80", "kubernetes.default.svc.cluster.local:80", "models.internal:0443", "models.internal:00443",
	}
	for _, h := range bad {
		t.Run(h, func(t *testing.T) {
			t.Parallel()
			doc := strings.Replace(valid, egress, `egress: { hosts: ["`+h+`"] }
    gatewayCredentials:`, 1)
			wantProblem(t, doc, install.CodeUnsafeRole, "/roles/coder/egress/hosts/0")
		})
	}
	for _, ok := range []string{"10.0.0.5:443", "8.8.8.8:443", "models.internal:443", "a1.example.com:8443", "192.168.1.10:443", "223.255.255.255:443", "100.100.100.201:443"} {
		doc := strings.Replace(valid, egress, `egress: { hosts: ["`+ok+`"] }
    gatewayCredentials:`, 1)
		doc = strings.Replace(doc, `host: "models.internal:443"`, `host: "`+ok+`"`, 1)
		mustParse(t, doc)
	}
}

func TestParse_GatewayOperationsRejectTraversal(t *testing.T) { // RUN-4
	t.Parallel()
	valid := validYAML(t)
	for _, op := range []string{
		"GET /v1/../admin", "GET /v1/./x", "GET /..", "GET /.", "GET /v1/..", "GET /../x",
		"GET /v1/%2e%2e/x", "GET /v1/%2E%2E/x", "GET /v1/%2e/x", "GET /v1/.%2e/x", "GET /v1/%2E", "POST /a/%2e%2E/b",
		// Round 2: separators, double encoding and matrix parameters the gateway and the origin could read differently.
		"GET /..;", "GET /.;", "GET /%252e%252e", "GET /..%2f", "GET /%2f", "GET /%5c..%5c", "GET /%u002e", "GET /..%00",
		"GET /a;b=c/d", "GET /a//b", "GET /a/", "GET //a", "GET /a/b/", "GET /a%20b", "GET /a:b", "GET /a,b",
	} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			doc := strings.Replace(valid, `"POST /v1/messages"`, `"`+op+`"`, 1)
			ps := problemsOf(t, doc)
			if !has(ps, install.CodeUnsafeRole, "/roles/coder/gatewayCredentials/0/operations/0") && !has(ps, install.CodeSchema, "/roles/coder/gatewayCredentials/0/operations/0") {
				t.Errorf("problems = %v", ps)
			}
		})
	}
	for _, ok := range []string{"GET /v1/models/gpt.4.v2", "POST /v1/messages", "GET /", "GET /a_b/c~d/e-f.json"} {
		mustParse(t, strings.Replace(valid, `"POST /v1/messages"`, `"`+ok+`"`, 1))
	}
}

func TestAdmit_OversizedRecordIsNotHashed(t *testing.T) { // NFR-2
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	coder, _ := cfg.Role("coder")
	store := installtest.NewStore()
	// If Admit hashed first it would report a digest mismatch: the size check comes first.
	store.PutAs(coder.Qualification, make([]byte, 1<<20))
	wantDenied(t, cfg.Admit(t.Context(), "coder", store), install.ReasonMalformed)
}

func TestParse_TimersConfigured(t *testing.T) { // AGT-5, INT-15, PIP-15, REC-3, COST-4, COST-7
	t.Parallel()
	doc := replaceOnce(t, validYAML(t), "timers:\n  reviewRounds: 3\n  sameGateFailures: 3\n", `timers:
  reviewRounds: 7
  replans: 8
  acceptanceRepairs: 9
  inverseRetries: 10
  sameGateFailures: 11
  noProgressIterations: 12
  spendOverEstimateFactor: 14
`)
	doc = replaceOnce(t, doc, "denialAuditTimeoutSeconds: 5", "denialAuditTimeoutSeconds: 13")
	cfg := mustParse(t, doc)
	want := install.Timers{
		ReviewRounds: 7, Replans: 8, AcceptanceRepairs: 9, InverseRetries: 10,
		SameGateFailures: 11, NoProgressIterations: 12, SpendOverEstimateFactor: 14,
	}
	if diff := cmp.Diff(want, cfg.Timers()); diff != "" {
		t.Errorf("Timers (-want +got):\n%s", diff)
	}
	if got := cfg.AuthzConfig().DenialAuditTimeout; got != 13*time.Second {
		t.Errorf("DenialAuditTimeout = %v, want 13s", got)
	}
}

func TestParse_PurposeOnlyOnVerifyGates(t *testing.T) { // SEC-4
	t.Parallel()
	doc := replaceOnce(t, validYAML(t), "  union: []\n", `  union:
    - { purpose: secret-scan, name: smoke, producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit", mandatory: true }
`)
	wantProblem(t, doc, install.CodeInvalid, "/baseline/union/0/purpose")
}

func TestParse_GitHubPeopleAreNumericIDs(t *testing.T) { // SEC-6, SEC-10
	t.Parallel()
	valid := validYAML(t)
	for _, id := range []string{"octocat", "0123", "12a", "-5", "1234567890123456789012", "a1"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			admin := replaceOnce(t, valid, `{ forge: github, id: "12345" }`, `{ forge: github, id: "`+id+`" }`)
			if ps := problemsOf(t, admin); !has(ps, install.CodeInvalid, "/admins/0/id") && !has(ps, install.CodeSchema, "/admins/0/id") {
				t.Errorf("admin %q: problems = %v", id, ps)
			}
			approver := replaceOnce(t, valid, `{ forge: github, id: "111" }`, `{ forge: github, id: "`+id+`" }`)
			if ps := problemsOf(t, approver); !has(ps, install.CodeInvalid, "/policyApprovers/members/0/id") && !has(ps, install.CodeSchema, "/policyApprovers/members/0/id") {
				t.Errorf("approver %q: problems = %v", id, ps)
			}
		})
	}
	wantProblem(t, replaceOnce(t, valid, `{ forge: github, id: "12345" }`, `{ forge: github, id: "octocat" }`), install.CodeInvalid, "/admins/0/id")
}

func TestParse_RegistryBacksCheckGatesForContracts(t *testing.T) { // CON-4
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	parser, err := contract.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	c, err := parser.Parse("", []byte(`apiVersion: factory/v1alpha1
kind: Contract
paths:
  writable: ['src/**']
gates:
  verify:
    - name: unit
      producerId: "github-app:15368"
      workflowId: "ci.yml"
      workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4"
      checkId: "unit"
      mandatory: true
`))
	if err != nil {
		t.Fatal(err)
	}
	set, err := contract.NewSet(strings.Repeat("a", 40), c)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.Compile(set, baselineOf(t, cfg), cfg.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if gerr := policy.CheckGates(t.Context(), cfg.GateRegistry(), nil); gerr != nil {
		t.Errorf("CheckGates with the install's registry: %v", gerr)
	}
	lacking := mustParse(t, replaceOnce(t, validYAML(t), `  - { producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit" }`+"\n", ""))
	err = policy.CheckGates(t.Context(), lacking.GateRegistry(), nil)
	var ve *contract.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 1 || ve.Problems[0].Code != contract.CodeUnregisteredGate {
		t.Errorf("CheckGates with a registry that lacks the gate = %v, want one unregistered-gate problem", err)
	}
}

func TestParse_Base64MustBeCanonicalText(t *testing.T) { // NFR-2
	t.Parallel()
	valid := validYAML(t)
	key := qualifier().PublicKey()
	for name, bad := range map[string]string{
		"trailing LF":       key + `\n`,
		"trailing CR LF":    key + `\r\n`,
		"LF inside":         key[:20] + `\n` + key[20:],
		"CR inside":         key[:20] + `\r` + key[20:],
		"unpadded":          strings.TrimSuffix(key, "="),
		"url-safe alphabet": strings.NewReplacer("+", "-", "/", "_").Replace(key) + "A",
	} {
		t.Run("key "+name, func(t *testing.T) {
			t.Parallel()
			doc := strings.Replace(valid, `key: "`+key+`"`, `key: "`+bad+`"`, 1)
			if ps := problemsOf(t, doc); !has(ps, install.CodeInvalid, "/qualifierKeys/0/key") && !has(ps, install.CodeSchema, "/qualifierKeys/0/key") {
				t.Errorf("problems = %v", ps)
			}
		})
	}
	cfg := mustParse(t, valid)
	coder, _ := cfg.Role("coder")
	good := qualifier().Record(coder.TupleDigest(), install.ResultPass)
	for name, sig := range map[string]string{
		"trailing LF":    good.Signature + "\n",
		"trailing CR LF": good.Signature + "\r\n",
		"LF inside":      good.Signature[:30] + "\n" + good.Signature[30:],
		"CR inside":      good.Signature[:30] + "\r" + good.Signature[30:],
	} {
		t.Run("signature "+name, func(t *testing.T) {
			t.Parallel()
			rec := good
			rec.Signature = sig
			// A loose decoder reads this as the genuine signature, so only the shape check can refuse it.
			if raw, err := base64.StdEncoding.DecodeString(sig); err != nil || base64.StdEncoding.EncodeToString(raw) != good.Signature {
				t.Fatalf("the test input is not a whitespace variant of the signature: %v", err)
			}
			data, _ := installtest.Encode(rec)
			wantDenied(t, admitRecord(t, valid, data), install.ReasonBadSignature)
		})
	}
}

func TestLoad_ReadIsBounded(t *testing.T) { // SEC-1
	t.Parallel()
	// A tree whose Lstat understates the size: the read itself must stop at the cap.
	big := make([]byte, install.MaxFileSize+10)
	tree := liarFS{fstest.MapFS{"i.yaml": {Data: big, Mode: 0o644}}}
	_, err := install.Load(t.Context(), treeReader{tree: tree}, "repo-1", strings.Repeat("c", 40), "i.yaml")
	if !errors.Is(err, forge.ErrTooLarge) {
		t.Errorf("Load = %v, want ErrTooLarge", err)
	}
}

// liarFS reports every file as one byte long.
type liarFS struct{ fstest.MapFS }

func (l liarFS) Lstat(name string) (fs.FileInfo, error) {
	info, err := l.MapFS.Lstat(name)
	if err != nil {
		return nil, err
	}
	return smallInfo{info}, nil
}

type smallInfo struct{ fs.FileInfo }

func (smallInfo) Size() int64 { return 1 }

func TestRoleSource_CandidateApproversDoNotCount(t *testing.T) { // RUN-1, SEC-10
	t.Parallel()
	active := mustParse(t, validYAML(t))
	// The candidate adds a new approver, "777", and drops "222".
	candidate := mustParse(t, replaceOnce(t, validYAML(t),
		`members: [{ forge: github, id: "111" }, { forge: github, id: "222" }]`,
		`members: [{ forge: github, id: "111" }, { forge: github, id: "777" }]`))
	target := authz.Target{Scope: authz.Scope{Kind: authz.ScopeInstall, ID: "inst-1"}}
	user := func(id string) authz.Principal {
		return authz.Principal{Forge: "github", ID: id, Kind: authz.PrincipalUser}
	}
	for id, want := range map[string]bool{"111": true, "222": true, "777": false} {
		got, err := active.RoleSource().HasRole(t.Context(), user(id), authz.RolePolicyApprover, target)
		if err != nil || got != want {
			t.Errorf("active config, approver %s: %v, %v, want %v", id, got, err, want)
		}
	}
	// The candidate's own source would let 777 in: activation must ask the active config's source.
	if got, _ := candidate.RoleSource().HasRole(t.Context(), user("777"), authz.RolePolicyApprover, target); !got {
		t.Fatal("test setup: the candidate does not list 777")
	}
}
