// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"slices"

	"github.com/elliott-davis/lightsout/internal/contract"
)

// Install config identity.
const (
	// APIVersion is the only supported apiVersion.
	APIVersion = "factory/v1alpha1"
	// Kind is the only supported kind.
	Kind = "Install"
)

// PRD defaults, used when a field is absent (AGT-5, INT-15, PIP-15, REC-3, COST-7).
const (
	DefaultReviewRounds            = 3
	DefaultReplans                 = 3
	DefaultAcceptanceRepairs       = 3
	DefaultInverseRetries          = 3
	DefaultNoProgressIterations    = 5
	DefaultSpendOverEstimateFactor = 5
	// DefaultQuorum is the default number of distinct policy approvers an activation needs.
	DefaultQuorum = 2
	// DefaultDenialAuditTimeoutSeconds is authz's default.
	DefaultDenialAuditTimeoutSeconds = 5
)

// Installation identifies the install and the one forge it serves.
type Installation struct {
	ID    string `json:"id"`
	Forge string `json:"forge"`
	// ForgeHosts are extra forge host:port values (a self-hosted forge) that no role's egress or gateway credential may name.
	ForgeHosts []string `json:"forgeHosts,omitempty"`
}

// Person is a person as the forge's stable ID, never a login.
type Person struct {
	Forge string `json:"forge"`
	ID    string `json:"id"`
}

// Timers are the caps and breakers, each at least 1.
type Timers struct {
	ReviewRounds            int // AGT-5
	Replans                 int // INT-15
	AcceptanceRepairs       int // PIP-15
	InverseRetries          int // REC-3
	SameGateFailures        int // COST-4
	NoProgressIterations    int // COST-7
	SpendOverEstimateFactor int // COST-7
}

// TeamLimit is the concurrency limit of one team (COST-2).
type TeamLimit struct {
	AgentSessions int `json:"agentSessions"`
	CIRuns        int `json:"ciRuns"`
}

// TeamQuota is the limit of one team, named by the forge's stable team ID.
type TeamQuota struct {
	TeamID        string `json:"teamId"`
	AgentSessions int    `json:"agentSessions"`
	CIRuns        int    `json:"ciRuns"`
}

// Quotas are the concurrency quotas and the CI rate limit (COST-2, COST-3).
type Quotas struct {
	Teams       []TeamQuota `json:"teams"`
	DefaultTeam TeamLimit   `json:"defaultTeam"`
	// CIRunsPerPRPerHour is counted per (repo ID, PR number).
	CIRunsPerPRPerHour int `json:"ciRunsPerPRPerHour"`
}

// QualifierKey is an IT-controlled qualification runner's public key.
type QualifierKey struct {
	ID  string `json:"id"`
	Key string `json:"key"` // base64 of the 32-byte ed25519 public key
}

// Profile is the pinned runtime, harness and model of a role (RUN-6, AGT-7). Every field is pinned.
type Profile struct {
	Template Template `json:"template"`
	Runtime  Runtime  `json:"runtime"`
	Harness  Harness  `json:"harness"`
	Model    Model    `json:"model"`
	Endpoint Endpoint `json:"endpoint"`
	Tools    []Tool   `json:"tools"`
}

// Template pins the role definition.
type Template struct {
	Digest string `json:"digest"`
}

// Runtime pins the container image by digest.
type Runtime struct {
	Image string `json:"image"`
}

// Harness pins the coding harness.
type Harness struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Model pins the model.
type Model struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

// Endpoint pins the canonical endpoint and gateway route config.
type Endpoint struct {
	Digest string `json:"digest"`
}

// Tool is a tool the role may use, with its permissions.
type Tool struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Permissions []string `json:"permissions"`
}

// Egress is where a role's sandbox may connect: literal host:port values, deny by default.
type Egress struct {
	Hosts []string `json:"hosts"`
}

// GatewayCredential is a credential the gateway injects at egress. The sandbox never holds it (RUN-4).
type GatewayCredential struct {
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Operations []string `json:"operations"`
}

// RoleProfile is one enabled role. The zero value is not a role.
type RoleProfile struct {
	// Name is the role's name, the key of the roles map. It is part of the tuple digest.
	Name string `json:"-"`
	// Manifest is the install's deployment manifest digest, set by Config.Role. It is part of the tuple digest, so
	// re-pinning templates, sandboxes, tools or permissions through the manifest invalidates every qualification.
	Manifest           string              `json:"-"`
	Profile            Profile             `json:"profile"`
	Egress             Egress              `json:"egress"`
	GatewayCredentials []GatewayCredential `json:"gatewayCredentials"`
	SandboxSecrets     []string            `json:"sandboxSecrets"`
	// Qualification is the digest of the signed qualification record bytes (NFR-2).
	Qualification string `json:"qualification"`
}

func (r RoleProfile) clone() RoleProfile {
	r.Profile.Tools = slices.Clone(r.Profile.Tools)
	for i := range r.Profile.Tools {
		r.Profile.Tools[i].Permissions = slices.Clone(r.Profile.Tools[i].Permissions)
	}
	r.Egress.Hosts = slices.Clone(r.Egress.Hosts)
	r.GatewayCredentials = slices.Clone(r.GatewayCredentials)
	for i := range r.GatewayCredentials {
		r.GatewayCredentials[i].Operations = slices.Clone(r.GatewayCredentials[i].Operations)
	}
	r.SandboxSecrets = slices.Clone(r.SandboxSecrets)
	return r
}

// installGate is a baseline gate in the file: a contract gate plus its purpose.
type installGate struct {
	Purpose string `json:"purpose,omitempty"`
	Name    string `json:"name"`
	contract.GateRef
	Mandatory bool `json:"mandatory"`
}

// Baseline gate purposes (SEC-4).
const (
	PurposeSecretScan     = "secret-scan"
	PurposeDependencyScan = "dependency-scan"
)

// document is the install file as decoded. Optional numbers are pointers so an absent value takes its default.
type document struct {
	APIVersion         string       `json:"apiVersion"`
	Kind               string       `json:"kind"`
	Installation       Installation `json:"installation"`
	DeploymentManifest string       `json:"deploymentManifest"`
	PolicyApprovers    struct {
		Quorum  *int     `json:"quorum"`
		Members []Person `json:"members"`
	} `json:"policyApprovers"`
	Admins []Person `json:"admins"`
	Timers struct {
		ReviewRounds            *int `json:"reviewRounds"`
		Replans                 *int `json:"replans"`
		AcceptanceRepairs       *int `json:"acceptanceRepairs"`
		InverseRetries          *int `json:"inverseRetries"`
		SameGateFailures        int  `json:"sameGateFailures"`
		NoProgressIterations    *int `json:"noProgressIterations"`
		SpendOverEstimateFactor *int `json:"spendOverEstimateFactor"`
	} `json:"timers"`
	Quotas           Quotas `json:"quotas"`
	ContractDefaults struct {
		SwitchStaleDays     int `json:"switchStaleDays"`
		SwitchAbandonedDays int `json:"switchAbandonedDays"`
		ReviewBudgetLines   int `json:"reviewBudgetLines"`
	} `json:"contractDefaults"`
	Baseline struct {
		Verify    []installGate `json:"verify"`
		Union     []installGate `json:"union"`
		Reviewers struct {
			PR       string `json:"pr"`
			Security string `json:"security"`
		} `json:"reviewers"`
		KnownAgents []string  `json:"knownAgents"`
		Protected   *[]string `json:"protected"`
	} `json:"baseline"`
	GateRegistry []contract.GateRef `json:"gateRegistry"`
	Decisions    struct {
		Expiry                    map[string]int `json:"expiry"`
		DenialAuditTimeoutSeconds *int           `json:"denialAuditTimeoutSeconds"`
	} `json:"decisions"`
	QualifierKeys []QualifierKey         `json:"qualifierKeys"`
	Roles         map[string]RoleProfile `json:"roles"`
}
