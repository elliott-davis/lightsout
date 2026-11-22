// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/version"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"--version"}, wantStdout: version.String()},
		{name: "no args", wantErr: true, wantStderr: "usage: factory"},
		{name: "bad flag", args: []string{"--nope"}, wantErr: true, wantStderr: "usage: factory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			err := run(context.Background(), tt.args, &stdout, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

const testRev = "a4ac7e7ccc7544f12d78ba75fd84289a903511f3"

const gateYAML = `gates:
  verify:
    - name: build
      producerId: github-app:1
      workflowId: 7
      workflowRevision: ` + testRev + `
      checkId: build
      mandatory: true
`

// writeTree writes files (relative path to content) under a new temp dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const contractHead = "apiVersion: factory/v1alpha1\nkind: Contract\n"

func goodTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		".factory.yaml":     contractHead + "paths:\n  writable: ['src/**']\n" + gateYAML,
		"a/.factory.yaml":   contractHead,
		"b/.factory.yaml":   contractHead,
		"src/main.go":       "package main\n",
		"README.md":         "hi\n",
		"a/deep/.keep":      "",
		"unrelated/file.go": "package x\n",
	})
}

// looseningTree has a loosening in b, which a change to a alone does not touch.
func looseningTree(t *testing.T) string {
	t.Helper()
	return writeTree(t, map[string]string{
		".factory.yaml":   contractHead + "paths:\n  writable: ['src/**']\n",
		"a/.factory.yaml": contractHead,
		"b/.factory.yaml": contractHead + "paths:\n  writable: ['**']\n",
	})
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = run(t.Context(), args, &out, &errOut)
	return out.String(), errOut.String(), err
}

func TestContractSchema(t *testing.T) {
	t.Parallel()
	out, _, err := runCLI(t, "contract", "schema")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("schema output is not JSON: %v", err)
	}
	if _, ok := v["$schema"]; !ok {
		t.Errorf("schema lacks $schema: %.80s", out)
	}
}

func TestContractUsageErrors(t *testing.T) {
	t.Parallel()
	root := goodTree(t)
	digestOut, _, derr := runCLI(t, "contract", "trust-digest")
	if derr != nil {
		t.Fatal(derr)
	}
	currentDigest := strings.TrimSpace(digestOut)
	for name, args := range map[string][]string{
		"no subcommand":             {"contract"},
		"unknown subcommand":        {"contract", "frobnicate"},
		"validate no revision":      {"contract", "validate", "--root", root},
		"validate bad revision":     {"contract", "validate", "--root", root, "--revision", "main"},
		"validate uppercase rev":    {"contract", "validate", "--root", root, "--revision", strings.ToUpper(testRev)},
		"validate stray arg":        {"contract", "validate", "--root", root, "--revision", testRev, "extra"},
		"explain no revision":       {"contract", "explain", "--root", root, "a.go"},
		"explain no path":           {"contract", "explain", "--root", root, "--revision", testRev},
		"unknown flag":              {"contract", "validate", "--nope"},
		"validate no registry flag": {"contract", "validate", "--root", root, "--revision", testRev},
		"both registry flags": {
			"contract", "validate", "--root", root, "--revision", testRev,
			"--gate-registry", "x.json", "--no-gate-registry",
		},
		"changed names a file": {
			"contract", "validate", "--root", root, "--revision", testRev,
			"--no-gate-registry", "--changed", "svc/.factory.yaml",
		},
		"changed names the root file": {
			"contract", "validate", "--root", root, "--revision", testRev,
			"--no-gate-registry", "--changed", ".factory.yaml",
		},
		"explain flag after path": {"contract", "explain", "--root", root, "--revision", testRev, "src/main.go", "--json"},
		"trust-digest stray arg":  {"contract", "trust-digest", "x"},
		"matching digest without changed": {
			"contract", "validate", "--root", root, "--revision", testRev,
			"--no-gate-registry", "--trusted-digest", currentDigest,
		},
		"stale digest without changed": {
			"contract", "validate", "--root", root, "--revision", testRev,
			"--no-gate-registry", "--trusted-digest", strings.Repeat("0", 64),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, stderr, err := runCLI(t, args...)
			if !errors.Is(err, errUsage) {
				t.Errorf("error = %v, want a usage error", err)
			}
			if !strings.Contains(stderr, "usage") && !strings.Contains(stderr, "flag provided but not defined") {
				t.Errorf("stderr = %q, want usage", stderr)
			}
		})
	}
}

func TestContractValidate_GoodTree(t *testing.T) {
	t.Parallel()
	out, stderr, err := runCLI(t, "contract", "validate", "--root", goodTree(t), "--revision", testRev, "--no-gate-registry")
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "ok:") {
		t.Errorf("stdout = %q, want ok", out)
	}
	if !strings.Contains(stderr, "not checked against a registry") {
		t.Errorf("stderr = %q, want the note that gates were not checked", stderr)
	}
}

func TestContractValidate_Loosening(t *testing.T) { // CON-12
	t.Parallel()
	root := looseningTree(t)
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry")
	if err == nil || !strings.Contains(out, "b/.factory.yaml") || !strings.Contains(out, "[loosening]") {
		t.Errorf("validate = %v, stdout %q, want a loosening problem on b", err, out)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Errorf("stdout = %q, want one problem per line", out)
	}
}

func TestContractValidate_ChangedLimitsScope(t *testing.T) { // CON-13
	t.Parallel()
	root := looseningTree(t)
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry", "--changed", "a")
	if err == nil || !strings.Contains(out, `"b/.factory.yaml"`) {
		t.Errorf("without a trusted digest: error = %v, stdout %q, want a full validation that reports b", err, out)
	}
	digest, _, err := runCLI(t, "contract", "trust-digest")
	if err != nil {
		t.Fatal(err)
	}
	digest = strings.TrimSpace(digest)
	out, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry", "--changed", "a", "--trusted-digest", digest)
	if err != nil || !strings.Contains(out, "checked 2 of 3") {
		t.Errorf("with the trusted digest: error = %v, stdout %q, want 2 of 3 checked", err, out)
	}
	// A digest for other defaults is stale: everything is validated, and b is reported.
	_, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry", "--changed", "a",
		"--trusted-digest", digest, "--switch-stale-days", "99")
	if err == nil {
		t.Error("a stale digest still scoped the validation")
	}
	_, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry", "--changed", "b")
	if err == nil {
		t.Error("b changed: validate passed, want the loosening")
	}
}

func TestContractValidate_GateRegistry(t *testing.T) { // CON-4, SEC-11
	t.Parallel()
	root := goodTree(t)
	const registeredBuild = `[{"producerId":"github-app:1","workflowId":7,"workflowRevision":"` + testRev + `","checkId":"build"}]`
	tests := []struct {
		name     string
		registry string
		wantErr  bool
		wantOut  string
	}{
		{"registered", registeredBuild, false, "ok:"},
		{"unregistered", `[]`, true, "[unregistered-gate]"},
		{"wrong revision", `[{"producerId":"github-app:1","workflowId":7,"workflowRevision":"` + strings.Repeat("c", 40) + `","checkId":"build"}]`, true, "[unregistered-gate]"},
		{"malformed", `[{"producerId":`, true, ""},
		{"unknown field", `[{"producerId":"x","workflowId":7,"workflowRevision":"` + testRev + `","checkId":"build","extra":1}]`, true, ""},
		{"trailing data", registeredBuild + `[]`, true, ""},
		{"not an array", `{"producerId":"x"}`, true, ""},
		{"duplicate key", `[{"producerId":"x","producerId":"github-app:1","workflowId":7,"workflowRevision":"` + testRev + `","checkId":"build"}]`, true, ""},
		{"case-variant key", `[{"ProducerID":"github-app:1","workflowId":7,"workflowRevision":"` + testRev + `","checkId":"build"}]`, true, ""},
		{"missing field", `[{"producerId":"github-app:1","workflowId":7,"checkId":"build"}]`, true, ""},
		{"empty producer", `[{"producerId":"","workflowId":7,"workflowRevision":"` + testRev + `","checkId":"build"}]`, true, ""},
		{"empty check", `[{"producerId":"github-app:1","workflowId":7,"workflowRevision":"` + testRev + `","checkId":""}]`, true, ""},
		{"short revision", `[{"producerId":"github-app:1","workflowId":7,"workflowRevision":"abc123","checkId":"build"}]`, true, ""},
		{"uppercase revision", `[{"producerId":"github-app:1","workflowId":7,"workflowRevision":"` + strings.ToUpper(testRev) + `","checkId":"build"}]`, true, ""},
		{"too large", registeredBuild[:len(registeredBuild)-1] + strings.Repeat(" ", 1<<20) + `]`, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := filepath.Join(t.TempDir(), "registry.json")
			content := tt.registry
			decodeFailure := tt.wantErr && tt.wantOut == ""
			if decodeFailure && strings.HasPrefix(content, "[{") {
				// Put a valid, registered entry first, so the failure cannot be an unregistered gate.
				content = registeredBuild[:len(registeredBuild)-1] + "," + content[1:]
			}
			if err := os.WriteFile(reg, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			// The baseline gates are none in the CLI defaults, so only build is asked about.
			out, stderr, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--gate-registry", reg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %t (stdout %q)", err, tt.wantErr, out)
			}
			if decodeFailure {
				assertDecodeFailure(t, err, out)
			}
			if !strings.Contains(out, tt.wantOut) {
				t.Errorf("stdout = %q, want %q", out, tt.wantOut)
			}
			if strings.Contains(stderr, "not checked against a registry") {
				t.Errorf("stderr = %q, want no note when a registry is given", stderr)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev,
			"--gate-registry", filepath.Join(t.TempDir(), "absent.json"))
		if err == nil {
			t.Error("a missing registry file passed")
		}
	})
}

func TestContractValidate_SymlinkedContract(t *testing.T) { // CON-1
	t.Parallel()
	root := goodTree(t)
	target := filepath.Join(root, "README.md")
	if err := os.Symlink(target, filepath.Join(root, "src", ".factory.yaml")); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry")
	if err == nil || !strings.Contains(out, "[symlink]") {
		t.Errorf("validate = %v, stdout %q, want a symlink problem", err, out)
	}
}

func TestContractValidate_HostileFileNameIsEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	root := goodTree(t)
	// A misnamed contract file whose directory name holds a newline and an escape.
	dir := root + "/evil\nforged: line\x1b[31m"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("file system rejects the name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".factory.yml"), []byte(contractHead), 0o644); err != nil {
		t.Skipf("file system rejects the name: %v", err)
	}
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry")
	if err == nil {
		t.Fatal("validate passed")
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\nforged:") {
		t.Errorf("stdout holds an unescaped control: %q", out)
	}
}

func TestContractExplain(t *testing.T) { // CON-13
	t.Parallel()
	root := goodTree(t)
	out, _, err := runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "src/main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`path: "src/main.go"`,
		`access: writable (source: ".factory.yaml")`,
		`switchStaleDays: 30 (source: "install default")`,
		`verify gate: name="build"`,
		`reviewer: "pr-reviewer"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	jsonOut, _, err := runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--json", "src/main.go")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if uerr := json.Unmarshal([]byte(jsonOut), &v); uerr != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", uerr, jsonOut)
	}
	if v["path"] != "src/main.go" {
		t.Errorf("JSON path = %v", v["path"])
	}
	// The flags configure the defaults.
	out, _, err = runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--switch-stale-days", "9", "src/main.go")
	if err != nil || !strings.Contains(out, "switchStaleDays: 9 ") {
		t.Errorf("explain with a flag = %v\n%s", err, out)
	}
	// An invalid path is an error.
	if _, _, err = runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "a/../b"); err == nil {
		t.Error("an invalid path passed")
	}
	// A tree with problems is not explained.
	_, _, err = runCLI(t, "contract", "explain", "--root", looseningTree(t), "--revision", testRev, "b/x.go")
	if err == nil {
		t.Error("explain of an invalid tree passed")
	}
}

func TestContractValidate_ChangedWithRegistry(t *testing.T) { // CON-4, CON-13
	t.Parallel()
	root := writeTree(t, map[string]string{
		".factory.yaml":     contractHead + "paths:\n  writable: ['**']\n",
		"svc/.factory.yaml": contractHead + gateYAML,
	})
	reg := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(reg, []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _, err := runCLI(t, "contract", "trust-digest")
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--changed", "svc",
		"--gate-registry", reg, "--trusted-digest", strings.TrimSpace(digest))
	if err == nil || !strings.Contains(out, "[unregistered-gate]") || !strings.Contains(out, `"svc/.factory.yaml" "/gates/verify/0"`) {
		t.Errorf("validate = %v, stdout %q, want an unregistered-gate problem on svc", err, out)
	}
}

func TestContractValidate_NoGateRegistryNote(t *testing.T) { // CON-4
	t.Parallel()
	_, stderr, err := runCLI(t, "contract", "validate", "--root", goodTree(t), "--revision", testRev, "--no-gate-registry")
	if err != nil || !strings.Contains(stderr, "not checked against a registry") {
		t.Errorf("error = %v, stderr %q, want success with the note", err, stderr)
	}
}

func TestContractValidate_KnownAgent(t *testing.T) { // AGD-3
	t.Parallel()
	root := writeTree(t, map[string]string{
		".factory.yaml": contractHead + "paths:\n  writable: ['**']\nagents:\n  verify: [x]\n",
	})
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry")
	if err == nil || !strings.Contains(out, "[unknown-agent]") {
		t.Errorf("without --known-agent: error = %v, stdout %q, want unknown-agent", err, out)
	}
	if _, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry", "--known-agent", "x"); err != nil {
		t.Errorf("with --known-agent x: %v", err)
	}
}

func TestContractExplain_CLIDefaults(t *testing.T) { // CON-9, CON-7
	t.Parallel()
	root := goodTree(t)
	base := []string{"contract", "explain", "--root", root, "--revision", testRev}
	run := func(extra ...string) string {
		t.Helper()
		out, _, err := runCLI(t, append(append(append([]string{}, base...), extra...), "src/main.go")...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for flagName, want := range map[string]string{
		"--switch-stale-days":     "switchStaleDays: 7 ",
		"--switch-abandoned-days": "switchAbandonedDays: 8 ",
		"--review-budget-lines":   "reviewBudgetLines: 9 ",
	} {
		value := strings.TrimSpace(strings.SplitN(strings.SplitN(want, ": ", 2)[1], " ", 2)[0])
		if out := run(flagName, value); !strings.Contains(out, want) {
			t.Errorf("%s %s: output lacks %q:\n%s", flagName, value, want, out)
		}
	}
	if out := run(); !strings.Contains(out, "switchAbandonedDays: 30 ") || !strings.Contains(out, "reviewBudgetLines: 300 ") {
		t.Errorf("defaults are not 30/30/300:\n%s", out)
	}
	out, _, err := runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, ".github/workflows/ci.yml")
	if err != nil || !strings.Contains(out, "protected: true") || !strings.Contains(out, `access: forbidden (source: "factory protected path")`) {
		t.Errorf("workflow explain = %v\n%s", err, out)
	}
	// A 64-digit revision is accepted.
	rev64 := strings.Repeat("a", 64)
	if _, _, err := runCLI(t, "contract", "explain", "--root", root, "--revision", rev64, "src/main.go"); err != nil {
		t.Errorf("64-hex revision: %v", err)
	}
}

func TestContractExplain_BadTreePrintsProblems(t *testing.T) { // CON-12
	t.Parallel()
	out, _, err := runCLI(t, "contract", "explain", "--root", looseningTree(t), "--revision", testRev, "b/x.go")
	if err == nil || !strings.Contains(out, `"b/.factory.yaml"`) || !strings.Contains(out, "[loosening]") {
		t.Errorf("explain = %v, stdout %q, want the loosening problem printed", err, out)
	}
}

func TestContractTrustDigest(t *testing.T) {
	t.Parallel()
	a, _, err := runCLI(t, "contract", "trust-digest")
	if err != nil || len(strings.TrimSpace(a)) != 64 {
		t.Fatalf("digest = %q, %v", a, err)
	}
	b, _, _ := runCLI(t, "contract", "trust-digest", "--known-agent", "x")
	if a == b {
		t.Error("the digest ignores --known-agent")
	}
}

func TestContractValidate_OneReportWithoutChanged(t *testing.T) { // CON-4, CON-12
	t.Parallel()
	root := writeTree(t, map[string]string{
		".factory.yaml":   contractHead + "paths:\n  writable: ['src/**']\n",
		"b/.factory.yaml": contractHead + "paths:\n  writable: ['**']\n" + gateYAML,
	})
	reg := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(reg, []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--gate-registry", reg)
	if err == nil || !strings.Contains(out, "[loosening]") || !strings.Contains(out, "[unregistered-gate]") {
		t.Errorf("validate = %v, stdout %q, want both the loosening and the unregistered gate", err, out)
	}
}

func TestContractValidate_FullNoteWhenDigestDoesNotMatch(t *testing.T) { // CON-13
	t.Parallel()
	root := goodTree(t)
	_, stderr, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry",
		"--changed", "a", "--trusted-digest", strings.Repeat("0", 64))
	if err != nil || !strings.Contains(stderr, "does not match") {
		t.Errorf("error = %v, stderr %q, want the full-validation note", err, stderr)
	}
	digest, _, _ := runCLI(t, "contract", "trust-digest")
	_, stderr, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry",
		"--changed", "a", "--trusted-digest", strings.TrimSpace(digest))
	if err != nil || strings.Contains(stderr, "does not match") {
		t.Errorf("error = %v, stderr %q, want no note for a matching digest", err, stderr)
	}
}

func TestContractOutput_HashIsEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	root := writeTree(t, map[string]string{
		".factory.yaml":                       contractHead + "paths:\n  writable: ['src/**']\n",
		"svc/##[error]approved/.factory.yaml": contractHead + "paths:\n  writable: ['**']\n",
	})
	out, _, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry")
	if err == nil || strings.Contains(out, "#") || !strings.Contains(out, "[loosening]") {
		t.Errorf("validate = %v, stdout %q, want a loosening with no raw #", err, out)
	}
	gate := strings.ReplaceAll(gateYAML, "name: build", "name: '##[stop-commands]x'")
	root = writeTree(t, map[string]string{".factory.yaml": contractHead + "paths:\n  writable: ['**']\n" + gate})
	out, _, err = runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--json", "a.go")
	if err != nil || strings.Contains(out, "#") || !strings.Contains(out, `\u0023\u0023[stop-commands]x`) {
		t.Errorf("explain --json = %v, stdout %q, want the name escaped", err, out)
	}
	out, _, err = runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "a.go")
	if err != nil || strings.Contains(out, "#") {
		t.Errorf("explain = %v, stdout %q, want no raw #", err, out)
	}
}

// hostileArg holds invalid UTF-8, newlines, a workflow command, an escape
// sequence and a legacy command.
const hostileArg = "evil\xff\n::error title=x::y\n\x1b[2Kok##[error]z"

// assertSafeStderr checks what main would print for err plus what run wrote.
func assertSafeStderr(t *testing.T, stderr string, err error) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(stderr)
	if err != nil {
		printError(&buf, err)
	}
	out := buf.String()
	for _, r := range out {
		if r == '\n' {
			continue
		}
		if !unicode.IsPrint(r) && r != '\t' || r == '#' || r == utf8.RuneError {
			t.Errorf("stderr holds the raw rune %U: %q", r, out)
			return
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "::") {
			t.Errorf("a line starts with ::: %q", line)
		}
	}
}

func TestContractErrors_HostileArgumentsAreEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	root := goodTree(t)
	for name, args := range map[string][]string{
		"explain path": {"contract", "explain", "--root", root, "--revision", testRev, "a/" + hostileArg},
		"changed value": {
			"contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry",
			"--changed", hostileArg,
		},
		"unknown flag":    {"contract", "validate", "--" + hostileArg},
		"unknown command": {"contract", hostileArg},
		"bad root":        {"contract", "validate", "--root", "/nonexistent/" + hostileArg, "--revision", testRev, "--no-gate-registry"},
		"registry path": {
			"contract", "validate", "--root", root, "--revision", testRev,
			"--gate-registry", "/nonexistent/" + hostileArg,
		},
		"top-level flag": {"--" + hostileArg},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, stderr, err := runCLI(t, args...)
			if err == nil {
				t.Fatal("want an error")
			}
			assertSafeStderr(t, stderr, err)
		})
	}
}

func TestContractValidate_NonUTF8DirectoryOnDisk(t *testing.T) { // SEC-1
	if runtime.GOOS != "linux" {
		t.Skip("only Linux file systems accept a non-UTF-8 name")
	}
	t.Parallel()
	root := goodTree(t)
	dir := root + "/evil\xff\n::error title=x::y\n\x1b[2Kok##[error]z"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("file system rejects the name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".factory.yml"), []byte(contractHead), 0o644); err != nil {
		t.Skipf("file system rejects the name: %v", err)
	}
	out, stderr, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry")
	if err == nil {
		t.Fatal("validate passed")
	}
	assertSafeStderr(t, stderr+out, err)
}

func assertDecodeFailure(t *testing.T, err error, stdout string) {
	t.Helper()
	if !strings.Contains(err.Error(), "decode gate registry") && !strings.Contains(err.Error(), "larger than") {
		t.Errorf("error = %v, want a registry decode error", err)
	}
	if strings.Contains(stdout, "[unregistered-gate]") {
		t.Errorf("stdout = %q, want no unregistered-gate problem", stdout)
	}
}
