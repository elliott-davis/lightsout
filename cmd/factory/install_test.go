// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const validInstallPath = "../../internal/install/testdata/valid.yaml"

// installYAML returns the shared valid install file with testRev's build gate registered, so goodTree's contract
// passes the registry check.
func installYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(validInstallPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	reg := `gateRegistry:` + "\n" + `  - { producerId: "github-app:1", workflowId: 7, workflowRevision: "` + testRev + `", checkId: "build" }` + "\n"
	if strings.Count(doc, "gateRegistry:\n") != 1 {
		t.Fatal("fixture has no gateRegistry line")
	}
	return strings.Replace(doc, "gateRegistry:\n", reg, 1)
}

func writeInstall(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "install.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallValidate_Valid(t *testing.T) { // RUN-1
	t.Parallel()
	out, _, err := runCLI(t, "install", "validate", writeInstall(t, installYAML(t)))
	if err != nil || strings.TrimSpace(out) != "ok" {
		t.Errorf("install validate = %v, stdout %q, want ok", err, out)
	}
	// The shared fixture itself validates.
	if _, _, err := runCLI(t, "install", "validate", validInstallPath); err != nil {
		t.Errorf("the fixture: %v", err)
	}
}

func TestInstallValidate_Problems(t *testing.T) { // SEC-4, AGD-3, SEC-1, RUN-6, CON-5
	t.Parallel()
	valid := installYAML(t)
	tests := map[string]struct {
		old, new string
		want     string
	}{
		"missing dependency scan": {"    - purpose: dependency-scan\n      name: dep-scan\n", "    - name: dep-scan\n", "[missing]"},
		"advisory baseline gate":  {"      checkId: \"secret-scan\"\n      mandatory: true", "      checkId: \"secret-scan\"\n      mandatory: false", `"/baseline/verify/0/mandatory"`},
		"identical reviewers":     {"security: security-reviewer", "security: pr-reviewer", `"/baseline/reviewers"`},
		"reviewer not enabled":    {"pr: pr-reviewer", "pr: ghost", `"/baseline/reviewers/pr"`},
		"sandbox secrets":         {"    sandboxSecrets: []", `    sandboxSecrets: [KEY]`, `"/roles/coder/sandboxSecrets"`},
		"wildcard egress": {`egress: { hosts: ["models.internal:443"] }
    gatewayCredentials:`, `egress: { hosts: ["*.internal:443"] }
    gatewayCredentials:`, `"/roles/coder/egress/hosts/0"`},
		"unpinned image":       {"registry.internal/agent@sha256:2222222222222222222222222222222222222222222222222222222222222222", "registry.internal/agent:latest", "runtime/image"},
		"quorum above members": {"quorum: 2", "quorum: 3", `"/policyApprovers/quorum"`},
		"zero timer":           {"  reviewRounds: 3\n", "  reviewRounds: 0\n", `"/timers/reviewRounds"`},
		"unknown field":        {"kind: Install\n", "kind: Install\ncommand: x\n", "[unknown-field]"},
		"root-only CODEOWNERS": {"    - \".github/CODEOWNERS\"\n", "", `"/baseline/protected"`},
		"unsafe yaml":          {"kind: Install\n", "kind: &a Install\n", "[unsafe-yaml]"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := writeInstall(t, strings.Replace(valid, tt.old, tt.new, 1)) // the first occurrence: the coder
			if !strings.Contains(valid, tt.old) {
				t.Fatalf("%q is not in the fixture", tt.old)
			}
			out, _, err := runCLI(t, "install", "validate", path)
			if err == nil || !strings.Contains(err.Error(), "problem(s)") {
				t.Fatalf("error = %v, want a validation failure", err)
			}
			if !strings.Contains(out, tt.want) || strings.Contains(out, "ok") && !strings.Contains(out, "[") {
				t.Errorf("stdout = %q, want it to contain %q", out, tt.want)
			}
		})
	}
}

func TestInstallCommand_Usage(t *testing.T) { // RUN-1
	t.Parallel()
	for name, args := range map[string][]string{
		"no command": {"install"},
		"unknown":    {"install", "frobnicate"},
		"no file":    {"install", "validate"},
		"too many":   {"install", "validate", "a", "b"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, stderr, err := runCLI(t, args...)
			if err == nil || !strings.Contains(stderr, "usage") {
				t.Errorf("error = %v, stderr %q, want a usage error", err, stderr)
			}
		})
	}
	if _, _, err := runCLI(t, "install", "validate", filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing file passed")
	}
	big := filepath.Join(t.TempDir(), "big.yaml")
	if err := os.WriteFile(big, []byte("# "+strings.Repeat("x", 3<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCLI(t, "install", "validate", big)
	if err == nil || !strings.Contains(out, "[too-large]") {
		t.Errorf("a 3 MiB file: %v, stdout %q, want too-large", err, out)
	}
}

func TestInstallValidate_HostileOutputIsEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	doc := installYAML(t) + "\"evil\\n##[error]x\": 1\n"
	out, _, err := runCLI(t, "install", "validate", writeInstall(t, doc))
	if err == nil {
		t.Fatal("hostile key accepted")
	}
	if strings.Count(out, "\n") != strings.Count(strings.TrimRight(out, "\n"), "\n")+1 || strings.Contains(out, "##[") {
		t.Errorf("stdout is not one escaped line per problem: %q", out)
	}
}

func TestContractValidate_Install(t *testing.T) { // CON-4, CON-5, CON-9
	t.Parallel()
	root := goodTree(t)
	install := writeInstall(t, installYAML(t))

	// No registry flag is needed: the install config is the registry, and there is no interim note.
	out, stderr, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--install", install)
	if err != nil || !strings.Contains(out, "ok:") {
		t.Fatalf("validate --install = %v, stdout %q", err, out)
	}
	if strings.Contains(stderr, "interim") {
		t.Errorf("stderr = %q, want no interim note with --install", stderr)
	}

	// The registry comes from the install config: a gate it does not register fails.
	other := writeInstall(t, strings.Replace(installYAML(t), `  - { producerId: "github-app:1", workflowId: 7, workflowRevision: "`+testRev+`", checkId: "build" }`+"\n", "", 1))
	out, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--install", other)
	if err == nil || !strings.Contains(out, "[unregistered-gate]") {
		t.Errorf("an unregistered gate: %v, stdout %q", err, out)
	}

	// Known agents come from the install config.
	agents := writeTree(t, map[string]string{".factory.yaml": contractHead + "paths:\n  writable: ['**']\nagents:\n  verify: [payments-specialist]\n"})
	out, _, err = runCLI(t, "contract", "validate", "--root", agents, "--revision", testRev, "--install", install)
	if err != nil {
		t.Errorf("known agent from the install config: %v\n%s", err, out)
	}
	out, _, err = runCLI(t, "contract", "validate", "--root", agents, "--revision", testRev, "--no-gate-registry")
	if err == nil || !strings.Contains(out, "[unknown-agent]") {
		t.Errorf("without --install the agent is unknown: %v\n%s", err, out)
	}

	// An invalid install file fails before any contract is read, and prints its problems.
	bad := writeInstall(t, strings.Replace(installYAML(t), "security: security-reviewer", "security: pr-reviewer", 1))
	out, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--install", bad)
	if err == nil || !strings.Contains(out, `"/baseline/reviewers"`) {
		t.Errorf("a bad install config: %v\n%s", err, out)
	}
	if _, _, err = runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--install", filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing install file passed")
	}
}

func TestContractCommands_InstallExcludesInterimFlags(t *testing.T) { // CON-9
	t.Parallel()
	root := goodTree(t)
	install := writeInstall(t, installYAML(t))
	registry := writeInstall(t, "[]")
	interim := map[string][]string{
		"known agent":    {"--known-agent", "x"},
		"stale days":     {"--switch-stale-days", "5"},
		"abandoned days": {"--switch-abandoned-days", "5"},
		"review budget":  {"--review-budget-lines", "5"},
		// Even the value equal to the default is refused: the flag is the conflict, not its value.
		"stale days at the default": {"--switch-stale-days", "30"},
	}
	for name, extra := range interim {
		for _, cmd := range [][]string{{"contract", "validate", "--root", root, "--revision", testRev}, {"contract", "explain", "--root", root, "--revision", testRev}, {"contract", "trust-digest"}} {
			t.Run(name+" "+cmd[1], func(t *testing.T) {
				t.Parallel()
				args := append(append(append([]string{}, cmd...), "--install", install), extra...)
				if cmd[1] == "explain" {
					args = append(args, "src/main.go")
				}
				_, stderr, err := runCLI(t, args...)
				if err == nil || !strings.Contains(err.Error(), "cannot be combined with --install") || !strings.Contains(stderr, "usage") {
					t.Errorf("error = %v, stderr %q, want a usage error", err, stderr)
				}
			})
		}
	}
	// The registry flags are refused too: the install config holds the registry.
	for _, extra := range [][]string{{"--gate-registry", registry}, {"--no-gate-registry"}} {
		_, stderr, err := runCLI(t, append([]string{"contract", "validate", "--root", root, "--revision", testRev, "--install", install}, extra...)...)
		if err == nil || !strings.Contains(stderr, "usage") {
			t.Errorf("%v with --install: error = %v, stderr %q", extra, err, stderr)
		}
	}
	// Without --install the flags still work, with an interim note.
	_, stderr, err := runCLI(t, "contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry", "--switch-stale-days", "5")
	if err != nil || !strings.Contains(stderr, "interim") {
		t.Errorf("interim flags: %v, stderr %q, want success with the interim note", err, stderr)
	}
}

func TestContractCommands_InterimNote(t *testing.T) { // CON-9
	t.Parallel()
	root := goodTree(t)
	for _, args := range [][]string{
		{"contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry"},
		{"contract", "explain", "--root", root, "--revision", testRev, "src/main.go"},
		{"contract", "trust-digest"},
	} {
		_, stderr, err := runCLI(t, args...)
		if err != nil || !strings.Contains(stderr, "interim baseline and defaults") {
			t.Errorf("%s: error = %v, stderr %q, want the interim note", args[1], err, stderr)
		}
	}
}

func TestContractTrustDigest_Install(t *testing.T) { // RUN-1, CON-13
	t.Parallel()
	install := writeInstall(t, installYAML(t))
	digest := func(extra ...string) string {
		t.Helper()
		out, _, err := runCLI(t, append([]string{"contract", "trust-digest", "--install", install}, extra...)...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out)
	}
	// first uses the helper's default install revision; a and b name their own.
	first, a, b := digest(), digest("--install-revision", strings.Repeat("a", 40)), digest("--install-revision", strings.Repeat("b", 40))
	if len(first) != 64 || first == a || a == b || first == b {
		t.Errorf("the digest does not tell install revisions apart: %s %s %s", first, a, b)
	}
	if again := digest("--install-revision", strings.Repeat("a", 40)); again != a {
		t.Error("the digest is not stable")
	}
	// A changed install baseline changes the digest.
	changed := writeInstall(t, strings.Replace(installYAML(t), `    - "docs/CODEOWNERS"`, `    - "docs/CODEOWNERS"`+"\n"+`    - "extra/**"`, 1))
	out, _, err := runCLI(t, "contract", "trust-digest", "--install", changed)
	if err != nil || strings.TrimSpace(out) == first {
		t.Errorf("a changed baseline left the digest unchanged: %v", err)
	}
	// And it is not the interim digest.
	interim, _, _ := runCLI(t, "contract", "trust-digest")
	if strings.TrimSpace(interim) == first {
		t.Error("the install digest equals the interim digest")
	}
	for _, bad := range []string{"abc", strings.ToUpper(strings.Repeat("a", 40))} {
		_, badStderr, badErr := runCLI(t, "contract", "trust-digest", "--install", install, "--install-revision", bad)
		if badErr == nil || !strings.Contains(badStderr, "usage") {
			t.Errorf("--install-revision %q: %v, stderr %q", bad, badErr, badStderr)
		}
	}
	_, stderr, err := runCLI(t, "contract", "trust-digest", "--install-revision", strings.Repeat("a", 40))
	if err == nil || !strings.Contains(stderr, "usage") {
		t.Errorf("--install-revision without --install: %v, stderr %q", err, stderr)
	}
}

func TestContractExplain_Install(t *testing.T) { // CON-9, CON-7, CON-2
	t.Parallel()
	root := goodTree(t)
	install := writeInstall(t, installYAML(t))
	out, _, err := runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--install", install, "src/main.go")
	if err != nil || !strings.Contains(out, "switchStaleDays: 30 ") || !strings.Contains(out, "reviewBudgetLines: 300 ") {
		t.Errorf("explain --install = %v\n%s", err, out)
	}
	// Defaults come from the install config.
	tuned := writeInstall(t, strings.Replace(installYAML(t), "reviewBudgetLines: 300", "reviewBudgetLines: 123", 1))
	out, _, err = runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--install", tuned, "src/main.go")
	if err != nil || !strings.Contains(out, "reviewBudgetLines: 123 ") {
		t.Errorf("explain with tuned defaults = %v\n%s", err, out)
	}
	// Every CODEOWNERS location is protected, under the install config and under the interim defaults.
	for _, args := range [][]string{
		{"--install", install},
		{},
	} {
		for _, loc := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
			a := append(append([]string{"contract", "explain", "--root", root, "--revision", testRev}, args...), loc)
			out, _, err := runCLI(t, a...)
			if err != nil || !strings.Contains(out, "protected: true") {
				t.Errorf("explain %s %v = %v\n%s", loc, args, err, out)
			}
		}
	}
}

func TestContractCommands_NeedAPolicySource(t *testing.T) { // SEC-4, RUN-1
	t.Parallel()
	root := goodTree(t)
	install := writeInstall(t, installYAML(t))
	cmds := map[string][]string{
		"validate":     {"contract", "validate", "--root", root, "--revision", testRev, "--no-gate-registry"},
		"explain":      {"contract", "explain", "--root", root, "--revision", testRev, "src/main.go"},
		"trust-digest": {"contract", "trust-digest"},
	}
	withFlags := func(cmd []string, extra ...string) []string {
		out := append(append(append([]string{}, cmd[:2]...), extra...), cmd[2:]...)
		if slices.Contains(extra, "--install") {
			out = slices.DeleteFunc(out, func(a string) bool { return a == "--no-gate-registry" }) // the install config holds the registry
		}
		return out
	}
	for name, cmd := range cmds {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Neither an install config nor --interim-defaults: the interim policy has no SEC-4 gates, so it is never silent.
			_, stderr, err := runCLIRaw(t, cmd...)
			if err == nil || !strings.Contains(stderr, "usage") || !strings.Contains(err.Error(), "--interim-defaults") {
				t.Errorf("no policy source: error = %v, stderr %q, want a usage error", err, stderr)
			}
			// --interim-defaults runs, with the note.
			_, stderr, err = runCLIRaw(t, withFlags(cmd, "--interim-defaults")...)
			if err != nil || !strings.Contains(stderr, "interim baseline and defaults") {
				t.Errorf("--interim-defaults: error = %v, stderr %q", err, stderr)
			}
			// --install without --install-revision: the policy identity would be empty.
			_, stderr, err = runCLIRaw(t, withFlags(cmd, "--install", install)...)
			if err == nil || !strings.Contains(err.Error(), "--install-revision") || !strings.Contains(stderr, "usage") {
				t.Errorf("--install without a revision: error = %v, stderr %q", err, stderr)
			}
			// --install with --install-revision runs; --interim-defaults beside --install is a conflict.
			if _, _, err = runCLIRaw(t, withFlags(cmd, "--install", install, "--install-revision", installRev)...); err != nil {
				t.Errorf("--install with a revision: %v", err)
			}
			_, _, err = runCLIRaw(t, withFlags(cmd, "--install", install, "--install-revision", installRev, "--interim-defaults")...)
			if err == nil || !strings.Contains(err.Error(), "cannot be combined with --install") {
				t.Errorf("--install with --interim-defaults: %v", err)
			}
		})
	}
}

func TestContractExplain_ShowsInstallRevision(t *testing.T) { // RUN-1, CON-13
	t.Parallel()
	root := goodTree(t)
	install := writeInstall(t, installYAML(t))
	out, _, err := runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--install", install, "src/main.go")
	if err != nil || !strings.Contains(out, `installRevision: "`+installRev+`"`) {
		t.Errorf("text explain = %v\n%s", err, out)
	}
	out, _, err = runCLI(t, "contract", "explain", "--root", root, "--revision", testRev, "--install", install, "--json", "src/main.go")
	if err != nil || !strings.Contains(out, `"installRevision":"`+installRev+`"`) {
		t.Errorf("json explain = %v\n%s", err, out)
	}
}
