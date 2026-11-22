// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/codeowners"
	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/install"
)

// problemsOf parses doc and returns the problems, failing if it parses.
func problemsOf(t *testing.T, doc string) []install.Problem {
	t.Helper()
	cfg, err := install.Parse([]byte(doc))
	if err == nil {
		t.Fatalf("Parse succeeded, want a failure; roles %v", cfg.Roles())
	}
	var ve *install.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	return ve.Problems
}

func has(ps []install.Problem, code install.Code, field string) bool {
	for _, p := range ps {
		if p.Code == code && p.Field == field {
			return true
		}
	}
	return false
}

func wantProblem(t *testing.T, doc string, code install.Code, field string) {
	t.Helper()
	if ps := problemsOf(t, doc); !has(ps, code, field) {
		t.Errorf("problems %v lack [%s] at %q", ps, code, field)
	}
}

func TestParse_Valid(t *testing.T) { // AGT-5, INT-15, PIP-15, REC-3, COST-2, COST-3, COST-4, COST-7, CON-9
	t.Parallel()
	cfg := mustParse(t, validYAML(t))

	if diff := cmp.Diff(install.Timers{
		ReviewRounds: 3, Replans: 3, AcceptanceRepairs: 3, InverseRetries: 3,
		SameGateFailures: 3, NoProgressIterations: 5, SpendOverEstimateFactor: 5,
	}, cfg.Timers()); diff != "" {
		t.Errorf("Timers (-want +got):\n%s", diff)
	}
	wantQuotas := install.Quotas{
		Teams:              []install.TeamQuota{{TeamID: "github:team:9876", AgentSessions: 4, CIRuns: 8}},
		DefaultTeam:        install.TeamLimit{AgentSessions: 2, CIRuns: 4},
		CIRunsPerPRPerHour: 6,
	}
	if diff := cmp.Diff(wantQuotas, cfg.Quotas()); diff != "" {
		t.Errorf("Quotas (-want +got):\n%s", diff)
	}
	if got, want := cfg.Defaults(), (contract.Defaults{SwitchStaleDays: 30, SwitchAbandonedDays: 30, ReviewBudgetLines: 300}); got != want {
		t.Errorf("Defaults = %+v, want %+v", got, want)
	}

	b := baselineOf(t, cfg)
	if len(b.Verify) != 2 || !b.Verify[0].Mandatory || !b.Verify[1].Mandatory || len(b.Union) != 0 {
		t.Errorf("Baseline gates = %+v", b)
	}
	if b.PRReviewer != "pr-reviewer" || b.SecurityReviewer != "security-reviewer" ||
		!cmp.Equal(b.Reviewers, []string{"pr-reviewer", "security-reviewer"}) || !cmp.Equal(b.KnownAgents, []string{"payments-specialist"}) {
		t.Errorf("Baseline reviewers = %+v", b)
	}
	if b.InstallRevision != fixtureRevision {
		t.Errorf("InstallRevision = %q, want %q", b.InstallRevision, fixtureRevision)
	}
	if _, err := cfg.Baseline(); !errors.Is(err, install.ErrNoRevision) {
		t.Errorf("Baseline without an install revision = %v, want ErrNoRevision", err)
	}
	set, err := contract.NewSet(strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Compile(set, b, cfg.Defaults()); err != nil {
		t.Errorf("the baseline does not compile: %v", err)
	}

	if got := cfg.Roles(); !cmp.Equal(got, []string{"coder", "payments-specialist", "pr-reviewer", "security-reviewer"}) {
		t.Errorf("Roles = %v", got)
	}
	ac := cfg.AuthzConfig()
	if ac.Forge != "github" || ac.InstallID != "inst-1" || ac.DenialAuditTimeout != 5*time.Second ||
		!cmp.Equal(ac.Expiry, map[authz.Operation]time.Duration{authz.OpHalt: time.Hour}) {
		t.Errorf("AuthzConfig = %+v", ac)
	}
	if _, err := authz.New(ac, cfg.RoleSource(), nopAuditor{}, time.Now); err != nil {
		t.Errorf("authz.New rejects the install's config: %v", err)
	}
	if !cmp.Equal(cfg.Installation(), install.Installation{ID: "inst-1", Forge: "github"}) || !strings.HasPrefix(cfg.DeploymentManifest(), "sha256:") {
		t.Errorf("Installation = %+v, manifest %q", cfg.Installation(), cfg.DeploymentManifest())
	}
}

type nopAuditor struct{}

func (nopAuditor) Append(context.Context, audit.Record) (audit.Entry, error) {
	return audit.Entry{}, nil
}

func TestParse_Defaults(t *testing.T) { // AGT-5, INT-15, PIP-15, REC-3, COST-7
	t.Parallel()
	doc := replaceOnce(t, validYAML(t), "  reviewRounds: 3\n", "")
	cfg := mustParse(t, doc)
	want := install.Timers{
		ReviewRounds: install.DefaultReviewRounds, Replans: install.DefaultReplans,
		AcceptanceRepairs: install.DefaultAcceptanceRepairs, InverseRetries: install.DefaultInverseRetries,
		SameGateFailures: 3, NoProgressIterations: install.DefaultNoProgressIterations,
		SpendOverEstimateFactor: install.DefaultSpendOverEstimateFactor,
	}
	if want.ReviewRounds != 3 || want.Replans != 3 || want.AcceptanceRepairs != 3 || want.InverseRetries != 3 ||
		want.NoProgressIterations != 5 || want.SpendOverEstimateFactor != 5 {
		t.Fatalf("PRD defaults changed: %+v", want)
	}
	if diff := cmp.Diff(want, cfg.Timers()); diff != "" {
		t.Errorf("Timers (-want +got):\n%s", diff)
	}

	// The default quorum is 2, and it must be satisfiable.
	noQuorum := replaceOnce(t, validYAML(t), "  quorum: 2\n", "")
	if q := mustParse(t, noQuorum).PolicyApprovers().Quorum; q != 2 {
		t.Errorf("default quorum = %d, want 2", q)
	}
	oneMember := replaceOnce(t, noQuorum, `members: [{ forge: github, id: "111" }, { forge: github, id: "222" }]`, `members: [{ forge: github, id: "111" }]`)
	wantProblem(t, oneMember, install.CodeInvalid, "/policyApprovers/quorum")

	// Settings without a PRD number are required, never defaulted.
	required := map[string]struct{ old, field string }{
		"sameGateFailures":   {"  sameGateFailures: 3\n", "/timers"},
		"quotas":             {"quotas:\n  teams: [{ teamId: \"github:team:9876\", agentSessions: 4, ciRuns: 8 }]\n  defaultTeam: { agentSessions: 2, ciRuns: 4 }\n  ciRunsPerPRPerHour: 6\n", ""},
		"ciRunsPerPRPerHour": {"  ciRunsPerPRPerHour: 6\n", "/quotas"},
		"defaultTeam":        {"  defaultTeam: { agentSessions: 2, ciRuns: 4 }\n", "/quotas"},
		"contractDefaults":   {"contractDefaults: { switchStaleDays: 30, switchAbandonedDays: 30, reviewBudgetLines: 300 }\n", ""},
		"reviewBudgetLines":  {"contractDefaults: { switchStaleDays: 30, switchAbandonedDays: 30, reviewBudgetLines: 300 }", "contractDefaults: { switchStaleDays: 30, switchAbandonedDays: 30 }"},
	}
	for name, r := range required {
		t.Run("required "+name, func(t *testing.T) {
			t.Parallel()
			repl := ""
			if name == "reviewBudgetLines" {
				repl = r.field
				ps := problemsOf(t, replaceOnce(t, validYAML(t), r.old, repl))
				if !has(ps, install.CodeSchema, "/contractDefaults") {
					t.Errorf("problems = %v", ps)
				}
				return
			}
			ps := problemsOf(t, replaceOnce(t, validYAML(t), r.old, repl))
			if !has(ps, install.CodeSchema, r.field) {
				t.Errorf("problems = %v, want a schema problem at %q", ps, r.field)
			}
		})
	}
}

func TestParse_ValuesAtLeastOne(t *testing.T) { // AGT-5, INT-15, PIP-15, REC-3, COST-2, COST-3, COST-4, COST-7, CON-9
	t.Parallel()
	timers := []string{"reviewRounds", "replans", "acceptanceRepairs", "inverseRetries", "sameGateFailures", "noProgressIterations", "spendOverEstimateFactor"}
	for _, name := range timers {
		for _, bad := range []string{"0", "-1"} {
			t.Run(name+" "+bad, func(t *testing.T) {
				t.Parallel()
				doc := replaceOnce(t, validYAML(t), "timers:\n  reviewRounds: 3\n  sameGateFailures: 3\n",
					"timers:\n  sameGateFailures: 3\n  "+name+": "+bad+"\n")
				if name == "sameGateFailures" {
					doc = replaceOnce(t, validYAML(t), "  sameGateFailures: 3\n", "  sameGateFailures: "+bad+"\n")
				}
				wantProblem(t, doc, install.CodeSchema, "/timers/"+name)
			})
		}
	}
	others := map[string]struct{ old, new, field string }{
		"team agentSessions":  {"agentSessions: 4", "agentSessions: 0", "/quotas/teams/0/agentSessions"},
		"team ciRuns":         {"ciRuns: 8", "ciRuns: -3", "/quotas/teams/0/ciRuns"},
		"default agent":       {"defaultTeam: { agentSessions: 2", "defaultTeam: { agentSessions: 0", "/quotas/defaultTeam/agentSessions"},
		"default ci":          {"ciRuns: 4 }", "ciRuns: 0 }", "/quotas/defaultTeam/ciRuns"},
		"per PR hour":         {"ciRunsPerPRPerHour: 6", "ciRunsPerPRPerHour: 0", "/quotas/ciRunsPerPRPerHour"},
		"stale days":          {"switchStaleDays: 30", "switchStaleDays: 0", "/contractDefaults/switchStaleDays"},
		"abandoned days":      {"switchAbandonedDays: 30", "switchAbandonedDays: -1", "/contractDefaults/switchAbandonedDays"},
		"review budget":       {"reviewBudgetLines: 300", "reviewBudgetLines: 0", "/contractDefaults/reviewBudgetLines"},
		"denial audit":        {"denialAuditTimeoutSeconds: 5", "denialAuditTimeoutSeconds: 0", "/decisions/denialAuditTimeoutSeconds"},
		"expiry":              {"expiry: { halt: 3600 }", "expiry: { halt: 0 }", "/decisions/expiry/halt"},
		"quorum":              {"quorum: 2", "quorum: 0", "/policyApprovers/quorum"},
		"float":               {"ciRunsPerPRPerHour: 6", "ciRunsPerPRPerHour: 6.5", "/quotas/ciRunsPerPRPerHour"},
		"string number":       {"ciRunsPerPRPerHour: 6", `ciRunsPerPRPerHour: "6"`, "/quotas/ciRunsPerPRPerHour"},
		"quorum not a number": {"quorum: 2", "quorum: many", "/policyApprovers/quorum"},
	}
	for name, o := range others {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, replaceOnce(t, validYAML(t), o.old, o.new), install.CodeSchema, o.field)
		})
	}
}

func TestParse_DecisionsAndTeams(t *testing.T) { // SEC-10
	t.Parallel()
	wantProblem(t, replaceOnce(t, validYAML(t), "expiry: { halt: 3600 }", "expiry: { teleport: 60 }"),
		install.CodeInvalid, "/decisions/expiry/teleport")
	dupTeam := replaceOnce(t, validYAML(t), `teams: [{ teamId: "github:team:9876", agentSessions: 4, ciRuns: 8 }]`,
		`teams: [{ teamId: "github:team:9876", agentSessions: 4, ciRuns: 8 }, { teamId: "github:team:9876", agentSessions: 1, ciRuns: 1 }]`)
	wantProblem(t, dupTeam, install.CodeDuplicate, "/quotas/teams/1/teamId")
	foreign := replaceOnce(t, validYAML(t), `teamId: "github:team:9876"`, `teamId: "gitlab:team:9876"`)
	wantProblem(t, foreign, install.CodeInvalid, "/quotas/teams/0/teamId")
	// Authz accepts every expiry the install can produce.
	for _, op := range authz.Operations() {
		doc := replaceOnce(t, validYAML(t), "expiry: { halt: 3600 }", fmt.Sprintf("expiry: { %s: 60 }", op))
		cfg := mustParse(t, doc)
		if _, err := authz.New(cfg.AuthzConfig(), cfg.RoleSource(), nopAuditor{}, time.Now); err != nil {
			t.Errorf("authz.New with expiry for %s: %v", op, err)
		}
	}
	// No decisions section means no expiry and authz's own timeout.
	cfg := mustParse(t, replaceOnce(t, validYAML(t), "decisions: { expiry: { halt: 3600 }, denialAuditTimeoutSeconds: 5 }\n", ""))
	if ac := cfg.AuthzConfig(); len(ac.Expiry) != 0 || ac.DenialAuditTimeout != 5*time.Second {
		t.Errorf("AuthzConfig without decisions = %+v", ac)
	}
}

func TestParse_BaselineGates(t *testing.T) { // SEC-4, CON-5, CON-4
	t.Parallel()
	valid := validYAML(t)
	secretGate := `    - purpose: secret-scan
      name: secret-scan
      producerId: "github-app:15368"
      workflowId: "secret-scan.yml"
      workflowRevision: "a4ac7e7ccc7544f12d78ba75fd84289a903511f3"
      checkId: "secret-scan"
      mandatory: true
`
	t.Run("missing secret-scan purpose", func(t *testing.T) {
		t.Parallel()
		wantProblem(t, replaceOnce(t, valid, secretGate, ""), install.CodeMissing, "/baseline/verify")
		// A gate without a purpose does not satisfy it.
		wantProblem(t, replaceOnce(t, valid, "    - purpose: secret-scan\n      name: secret-scan\n", "    - name: secret-scan\n"), install.CodeMissing, "/baseline/verify")
	})
	t.Run("missing dependency-scan purpose", func(t *testing.T) {
		t.Parallel()
		wantProblem(t, replaceOnce(t, valid, "    - purpose: dependency-scan\n      name: dep-scan\n", "    - name: dep-scan\n"), install.CodeMissing, "/baseline/verify")
	})
	t.Run("no verify gates at all", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, secretGate, "")
		doc = replaceOnce(t, doc, "    - purpose: dependency-scan\n      name: dep-scan\n", "    - name: dep-scan\n")
		if ps := problemsOf(t, doc); len(ps) < 2 {
			t.Errorf("problems = %v, want both purposes reported", ps)
		}
	})
	t.Run("advisory baseline gate", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, "      checkId: \"secret-scan\"\n      mandatory: true", "      checkId: \"secret-scan\"\n      mandatory: false")
		wantProblem(t, doc, install.CodeInvalid, "/baseline/verify/0/mandatory")
	})
	t.Run("baseline gate missing from the registry", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, `  - { producerId: "github-app:15368", workflowId: "dep-scan.yml", workflowRevision: "a4ac7e7ccc7544f12d78ba75fd84289a903511f3", checkId: "dep-scan" }`+"\n", "")
		wantProblem(t, doc, install.CodeUnregisteredGate, "/baseline/verify/1")
	})
	t.Run("registered at a different revision", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, `workflowId: "dep-scan.yml", workflowRevision: "a4ac7e7ccc7544f12d78ba75fd84289a903511f3"`, `workflowId: "dep-scan.yml", workflowRevision: "c333333333333333333333333333333333333333"`)
		wantProblem(t, doc, install.CodeUnregisteredGate, "/baseline/verify/1")
	})
	t.Run("registered under another producer", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, `producerId: "github-app:15368", workflowId: "secret-scan.yml"`, `producerId: "github-app:99999", workflowId: "secret-scan.yml"`)
		wantProblem(t, doc, install.CodeUnregisteredGate, "/baseline/verify/0")
	})
	t.Run("duplicate purpose", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, "    - purpose: dependency-scan\n", "    - purpose: secret-scan\n")
		wantProblem(t, doc, install.CodeDuplicate, "/baseline/verify/1/purpose")
	})
	t.Run("unknown purpose", func(t *testing.T) {
		t.Parallel()
		wantProblem(t, replaceOnce(t, valid, "purpose: secret-scan", "purpose: license-scan"), install.CodeSchema, "/baseline/verify/0/purpose")
	})
	t.Run("an advisory union gate", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, "  union: []\n", `  union:
    - { name: smoke, producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit", mandatory: false }
`)
		wantProblem(t, doc, install.CodeInvalid, "/baseline/union/0/mandatory")
		ok := replaceOnce(t, valid, "  union: []\n", `  union:
    - { name: smoke, producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit", mandatory: true }
`)
		if got := baselineOf(t, mustParse(t, ok)).Union; len(got) != 1 {
			t.Errorf("union gates = %v", got)
		}
	})
	t.Run("duplicate baseline identity reaches contract's check", func(t *testing.T) {
		t.Parallel()
		doc := replaceOnce(t, valid, "  union: []\n", `  union:
    - { name: one, producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit", mandatory: true }
    - { name: two, producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit", mandatory: true }
`)
		wantProblem(t, doc, install.CodeBaseline, "/baseline")
	})
}

func TestParse_GateRegistry(t *testing.T) { // CON-4
	t.Parallel()
	valid := validYAML(t)
	dup := replaceOnce(t, valid, "gateRegistry:\n", `gateRegistry:
  - { producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit" }
`)
	wantProblem(t, dup, install.CodeDuplicate, "/gateRegistry/3")
	for name, repl := range map[string]string{
		"short revision":     `workflowRevision: "b5bd8f8"`,
		"uppercase revision": `workflowRevision: "B5BD8F8DDDD655F23BA89BE95FE5390BA14622F4"`,
		"branch name":        `workflowRevision: "main"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			doc := replaceOnce(t, valid, `workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4"`, repl)
			wantProblem(t, doc, install.CodeSchema, "/gateRegistry/2/workflowRevision")
		})
	}
	// The same identity at two pinned revisions is two registrations, not a duplicate.
	two := replaceOnce(t, valid, "gateRegistry:\n", `gateRegistry:
  - { producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "c333333333333333333333333333333333333333", checkId: "unit" }
`)
	cfg := mustParse(t, two)
	reg := cfg.GateRegistry()
	for _, rev := range []string{"b5bd8f8dddd655f23ba89be95fe5390ba14622f4", "c333333333333333333333333333333333333333"} {
		ok, err := reg.Registered(t.Context(), contract.GateRef{ProducerID: "github-app:15368", WorkflowID: "ci.yml", WorkflowRevision: rev, CheckID: "unit"})
		if err != nil || !ok {
			t.Errorf("revision %s registered = %v, %v", rev, ok, err)
		}
	}
	for name, ref := range map[string]contract.GateRef{
		"other revision": {ProducerID: "github-app:15368", WorkflowID: "ci.yml", WorkflowRevision: strings.Repeat("d", 40), CheckID: "unit"},
		"other producer": {ProducerID: "github-app:1", WorkflowID: "ci.yml", WorkflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", CheckID: "unit"},
		"other check":    {ProducerID: "github-app:15368", WorkflowID: "ci.yml", WorkflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", CheckID: "lint"},
		"empty":          {},
	} {
		if ok, _ := reg.Registered(t.Context(), ref); ok {
			t.Errorf("%s: an unregistered gate reads as registered", name)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if ok, err := reg.Registered(ctx, contract.GateRef{}); ok || err == nil {
		t.Errorf("cancelled context: %v, %v, want an error and not registered", ok, err)
	}
}

func TestParse_RegistryBacksCheckGates(t *testing.T) { // CON-4, SEC-4
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	set, err := contract.NewSet(strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	p, err := contract.Compile(set, baselineOf(t, cfg), cfg.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckGates(t.Context(), cfg.GateRegistry(), nil); err != nil {
		t.Errorf("CheckGates against the install's own registry: %v", err)
	}
	// A registry that lacks a baseline gate fails CheckGates: the registry is what it asks.
	lacking := mustParse(t, replaceOnce(t, validYAML(t), `  - { producerId: "github-app:15368", workflowId: "ci.yml", workflowRevision: "b5bd8f8dddd655f23ba89be95fe5390ba14622f4", checkId: "unit" }`+"\n", ""))
	if err := p.CheckGates(t.Context(), lacking.GateRegistry(), nil); err != nil {
		t.Errorf("the unit gate is not a baseline gate, CheckGates must not need it: %v", err)
	}
}

func TestParse_Reviewers(t *testing.T) { // AGD-3
	t.Parallel()
	valid := validYAML(t)
	same := replaceOnce(t, valid, "reviewers: { pr: pr-reviewer, security: security-reviewer }", "reviewers: { pr: pr-reviewer, security: pr-reviewer }")
	wantProblem(t, same, install.CodeInvalid, "/baseline/reviewers")
	for name, repl := range map[string]string{
		"pr not enabled":       "reviewers: { pr: ghost-reviewer, security: security-reviewer }",
		"security not enabled": "reviewers: { pr: pr-reviewer, security: ghost-reviewer }",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			doc := replaceOnce(t, valid, "reviewers: { pr: pr-reviewer, security: security-reviewer }", repl)
			field := "/baseline/reviewers/pr"
			if strings.HasPrefix(name, "security") {
				field = "/baseline/reviewers/security"
			}
			wantProblem(t, doc, install.CodeUnknownRole, field)
		})
	}
	// Both identical and not enabled report both faults.
	both := replaceOnce(t, valid, "reviewers: { pr: pr-reviewer, security: security-reviewer }", "reviewers: { pr: ghost, security: ghost }")
	ps := problemsOf(t, both)
	if !has(ps, install.CodeInvalid, "/baseline/reviewers") || !has(ps, install.CodeUnknownRole, "/baseline/reviewers/pr") {
		t.Errorf("problems = %v", ps)
	}
	// A role that is not listed is not enabled, even if knownAgents names it.
	known := replaceOnce(t, valid, "knownAgents: [payments-specialist]", "knownAgents: [payments-specialist, ghost]")
	wantProblem(t, known, install.CodeUnknownRole, "/baseline/knownAgents/1")
}

func TestParse_ProtectedPaths(t *testing.T) { // CON-5, CON-2
	t.Parallel()
	valid := validYAML(t)
	// Every CODEOWNERS location is protected by default and in the fixture.
	for _, doc := range []string{valid, replaceOnce(t, valid, `  protected:
    - ".github/workflows/**"
    - ".github/actions/**"
    - ".github/CODEOWNERS"
    - "CODEOWNERS"
    - "docs/CODEOWNERS"
`, "")} {
		prot := baselineOf(t, mustParse(t, doc)).Protected
		for _, loc := range codeowners.Locations() {
			found := false
			for _, p := range prot {
				found = found || p == loc
			}
			if !found {
				t.Errorf("protected %v lacks the CODEOWNERS location %s", prot, loc)
			}
		}
	}
	if diff := cmp.Diff(append([]string{".github/workflows/**", ".github/actions/**"}, codeowners.Locations()...), install.DefaultProtected()); diff != "" {
		t.Errorf("DefaultProtected (-want +got):\n%s", diff)
	}

	list := func(items ...string) string {
		var b strings.Builder
		b.WriteString("  protected:\n")
		for _, it := range items {
			fmt.Fprintf(&b, "    - %q\n", it)
		}
		return b.String()
	}
	const fixtureList = `  protected:
    - ".github/workflows/**"
    - ".github/actions/**"
    - ".github/CODEOWNERS"
    - "CODEOWNERS"
    - "docs/CODEOWNERS"
`
	for _, loc := range codeowners.Locations() {
		var rest []string
		for _, l := range codeowners.Locations() {
			if l != loc {
				rest = append(rest, l)
			}
		}
		t.Run("missing "+loc, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, replaceOnce(t, valid, fixtureList, list(append([]string{".github/workflows/**"}, rest...)...)), install.CodeInvalid, "/baseline/protected")
		})
	}
	t.Run("only the root file", func(t *testing.T) {
		t.Parallel()
		// The interim CLI default and the old doc example: a PR could add .github/CODEOWNERS.
		wantProblem(t, replaceOnce(t, valid, fixtureList, list(".github/workflows/**", ".github/actions/**", "CODEOWNERS")), install.CodeInvalid, "/baseline/protected")
	})
	t.Run("empty list", func(t *testing.T) {
		t.Parallel()
		wantProblem(t, replaceOnce(t, valid, fixtureList, "  protected: []\n"), install.CodeInvalid, "/baseline/protected")
	})
	t.Run("a directory pattern covers the files beneath it", func(t *testing.T) {
		t.Parallel()
		mustParse(t, replaceOnce(t, valid, fixtureList, list(".github/**", "CODEOWNERS", "docs/CODEOWNERS")))
		mustParse(t, replaceOnce(t, valid, fixtureList, list(".github", "CODEOWNERS", "docs")))
		mustParse(t, replaceOnce(t, valid, fixtureList, list("**")))
	})
	t.Run("a pattern that does not match the exact path is no cover", func(t *testing.T) {
		t.Parallel()
		wantProblem(t, replaceOnce(t, valid, fixtureList, list(".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS/x", "codeowners")), install.CodeInvalid, "/baseline/protected")
	})
	t.Run("an invalid pattern fails through contract", func(t *testing.T) {
		t.Parallel()
		wantProblem(t, replaceOnce(t, valid, fixtureList, list("**", "a//b")), install.CodeBaseline, "/baseline")
	})
}

func TestParse_People(t *testing.T) { // SEC-6, SEC-10
	t.Parallel()
	valid := validYAML(t)
	members := `members: [{ forge: github, id: "111" }, { forge: github, id: "222" }]`
	admins := "admins:\n  - { forge: github, id: \"12345\" }\n"
	tests := map[string]struct {
		old, new string
		code     install.Code
		field    string
	}{
		"empty admins":            {admins, "admins: []\n", install.CodeSchema, "/admins"},
		"no admins":               {admins, "", install.CodeSchema, ""},
		"empty approvers":         {members, "members: []", install.CodeSchema, "/policyApprovers/members"},
		"duplicate approver":      {members, `members: [{ forge: github, id: "111" }, { forge: github, id: "111" }]`, install.CodeDuplicate, "/policyApprovers/members/1"},
		"duplicate admin":         {admins, admins + "  - { forge: github, id: \"12345\" }\n", install.CodeDuplicate, "/admins/1"},
		"foreign forge approver":  {members, `members: [{ forge: github, id: "111" }, { forge: gitlab, id: "222" }]`, install.CodeInvalid, "/policyApprovers/members/1/forge"},
		"foreign forge admin":     {admins, "admins:\n  - { forge: gitlab, id: \"12345\" }\n", install.CodeInvalid, "/admins/0/forge"},
		"quorum zero":             {"quorum: 2", "quorum: 0", install.CodeSchema, "/policyApprovers/quorum"},
		"quorum above members":    {"quorum: 2", "quorum: 3", install.CodeInvalid, "/policyApprovers/quorum"},
		"login instead of an ID":  {members, `members: [{ forge: github, id: "alice smith" }, { forge: github, id: "222" }]`, install.CodeSchema, "/policyApprovers/members/0/id"},
		"extra field on a member": {members, `members: [{ forge: github, id: "111", login: alice }, { forge: github, id: "222" }]`, install.CodeUnknownField, "/policyApprovers/members/0/login"},
		"approvers missing":       {"policyApprovers:\n  quorum: 2\n  members: [{ forge: github, id: \"111\" }, { forge: github, id: \"222\" }]\n", "", install.CodeSchema, ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, replaceOnce(t, valid, tt.old, tt.new), tt.code, tt.field)
		})
	}
	// The same ID on the same forge listed as admin and approver is fine: they are different roles.
	cfg := mustParse(t, replaceOnce(t, valid, `id: "12345"`, `id: "111"`))
	if len(cfg.Admins()) != 1 || cfg.PolicyApprovers().Quorum != 2 || len(cfg.PolicyApprovers().Members) != 2 {
		t.Errorf("Admins %v, PolicyApprovers %+v", cfg.Admins(), cfg.PolicyApprovers())
	}
}

func TestConfig_ReturnsCopies(t *testing.T) { // RUN-1
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	b := baselineOf(t, cfg)
	b.Verify[0].Mandatory = false
	b.Protected[0] = "x"
	b.Reviewers[0] = "x"
	b.KnownAgents[0] = "x"
	if got := baselineOf(t, cfg); !got.Verify[0].Mandatory || got.Protected[0] == "x" || got.Reviewers[0] == "x" || got.KnownAgents[0] == "x" {
		t.Error("changing a returned Baseline changed the Config")
	}
	cfg.Admins()[0].ID = "x"
	cfg.PolicyApprovers().Members[0].ID = "x"
	if cfg.Admins()[0].ID == "x" || cfg.PolicyApprovers().Members[0].ID == "x" {
		t.Error("changing returned people changed the Config")
	}
	cfg.Quotas().Teams[0].CIRuns = 99
	if cfg.Quotas().Teams[0].CIRuns == 99 {
		t.Error("changing returned quotas changed the Config")
	}
	r, _ := cfg.Role("coder")
	r.Profile.Tools[0].Permissions[0] = "x:y"
	r.Egress.Hosts[0] = "x:1"
	r.GatewayCredentials[0].Operations[0] = "GET /x"
	r2, _ := cfg.Role("coder")
	if r2.Profile.Tools[0].Permissions[0] == "x:y" || r2.Egress.Hosts[0] == "x:1" || r2.GatewayCredentials[0].Operations[0] == "GET /x" {
		t.Error("changing a returned role changed the Config")
	}
	cfg.AuthzConfig().Expiry[authz.OpResume] = time.Second
	if _, ok := cfg.AuthzConfig().Expiry[authz.OpResume]; ok {
		t.Error("changing the returned AuthzConfig changed the Config")
	}
	if _, ok := cfg.Role("ghost"); ok {
		t.Error("Role(ghost) found a role")
	}
}

func TestWithRevision_PolicyIdentity(t *testing.T) { // RUN-1, CON-5
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	revA, revB := strings.Repeat("a", 40), strings.Repeat("b", 64)
	a, err := cfg.WithRevision(revA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cfg.WithRevision(revB)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Revision() != "" || a.Revision() != revA || baselineOf(t, a).InstallRevision != revA || baselineOf(t, b).InstallRevision != revB {
		t.Errorf("revisions: %q %q %q", cfg.Revision(), baselineOf(t, a).InstallRevision, baselineOf(t, b).InstallRevision)
	}
	digests := map[string]bool{}
	for _, c := range []*install.Config{cfg, a, b} {
		digests[contract.TrustDigest(baselineOf(t, c), c.Defaults())] = true
	}
	if len(digests) != 3 {
		t.Errorf("the trust digest does not tell install revisions apart: %v", digests)
	}
	for _, bad := range []string{"", "abc", strings.ToUpper(revA), strings.Repeat("g", 40), revA + "\n"} {
		if _, err := cfg.WithRevision(bad); err == nil {
			t.Errorf("WithRevision(%q) succeeded", bad)
		}
	}
	// Changing a baseline gate's pinned revision changes the policy identity at one install revision.
	pin := func(rev string) *install.Config {
		doc := validYAML(t)
		doc = strings.ReplaceAll(doc, `workflowId: "secret-scan.yml"`+"\n      workflowRevision: \"a4ac7e7ccc7544f12d78ba75fd84289a903511f3\"", `workflowId: "secret-scan.yml"`+"\n      workflowRevision: \""+rev+"\"")
		doc = strings.ReplaceAll(doc, `workflowId: "secret-scan.yml", workflowRevision: "a4ac7e7ccc7544f12d78ba75fd84289a903511f3"`, `workflowId: "secret-scan.yml", workflowRevision: "`+rev+`"`)
		c, err := mustParse(t, doc).WithRevision(revA)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	x, y := pin("a4ac7e7ccc7544f12d78ba75fd84289a903511f3"), pin("c333333333333333333333333333333333333333")
	if contract.TrustDigest(baselineOf(t, x), x.Defaults()) == contract.TrustDigest(baselineOf(t, y), y.Defaults()) {
		t.Error("changing a baseline gate left the trust digest unchanged")
	}
}

func TestParse_Hostile(t *testing.T) { // SEC-1
	t.Parallel()
	doc := validYAML(t) + "\"evil\\n##[error]x\\u202e\": 1\n"
	ps := problemsOf(t, doc)
	for _, p := range ps {
		for _, s := range []string{p.Field, p.Message, p.String()} {
			if strings.ContainsAny(s, "\n\r#\u202e") {
				t.Errorf("problem text %q carries an unescaped control or '#'", s)
			}
		}
	}
	if !has(ps, install.CodeUnknownField, "/evil\\u000a\\x23\\x23[error]x\\u202e") {
		t.Errorf("problems = %v", ps)
	}
	var ve *install.ValidationError
	_, err := install.Parse([]byte(doc))
	if !errors.As(err, &ve) || strings.ContainsAny(err.Error(), "\n#") {
		t.Errorf("error text %q", err)
	}
}

func TestParse_ManyProblemsAreCapped(t *testing.T) { // SEC-1
	t.Parallel()
	var b strings.Builder
	b.WriteString(validYAML(t))
	for i := range 150 {
		fmt.Fprintf(&b, "extra%d: 1\n", i)
	}
	ps := problemsOf(t, b.String())
	if len(ps) != 100 || ps[len(ps)-1].Code != install.CodeTooMany {
		t.Errorf("got %d problems, last %+v, want 100 ending in a too-many note", len(ps), ps[len(ps)-1])
	}
}

func TestSchema_EveryObjectClosed(t *testing.T) { // SEC-1
	t.Parallel()
	var doc any
	if err := json.Unmarshal(install.SchemaJSON(), &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch n := v.(type) {
		case map[string]any:
			_, hasProps := n["properties"]
			if (n["type"] == "object" || hasProps) && n["additionalProperties"] == nil {
				t.Errorf("schema node %s is not closed (additionalProperties must be set)", path)
			}
			if ap, ok := n["additionalProperties"]; ok {
				// Either false, or a schema for the values of a map (roles, expiry).
				if _, isSchema := ap.(map[string]any); !isSchema && ap != false {
					t.Errorf("schema node %s: additionalProperties = %v", path, ap)
				}
			}
			for k, c := range n {
				walk(path+"/"+k, c)
			}
		case []any:
			for i, c := range n {
				walk(fmt.Sprintf("%s/%d", path, i), c)
			}
		}
	}
	walk("#", doc)
}

func TestSchema_SharedDefsMatchContract(t *testing.T) { // CON-4
	t.Parallel()
	defs := func(raw []byte) map[string]any {
		var s struct {
			Defs map[string]any `json:"$defs"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s.Defs
	}
	c, i := defs(contract.SchemaJSON()), defs(install.SchemaJSON())
	for _, name := range []string{"name", "badPathShape", "producerId", "workflowId", "workflowRevision", "checkId"} {
		if diff := cmp.Diff(c[name], i[name]); diff != "" {
			t.Errorf("$defs/%s differs from the contract schema (-contract +install):\n%s", name, diff)
		}
	}
}
