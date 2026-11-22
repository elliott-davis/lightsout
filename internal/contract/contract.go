// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// APIVersion is the only supported apiVersion.
	APIVersion = "factory/v1alpha1"
	// Kind is the only supported kind.
	Kind = "Contract"
	// FileName is the name of a contract file in any directory.
	FileName = ".factory.yaml"
	// MaxFileSize is the largest accepted contract file, in bytes.
	MaxFileSize = 64 << 10
)

// Contract is a parsed .factory.yaml. A Contract obtained from a Set is shared
// with it and must be treated as read-only. Pointer fields distinguish "absent" from
// a declared zero value, which matters to the merge rules.
type Contract struct {
	Dir        string    `json:"-"` // repo-relative directory, "" for the repo root; set by the parser
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Paths      Paths     `json:"paths"`
	Gates      Gates     `json:"gates"`
	Agents     Agents    `json:"agents"`
	LightsOn   *bool     `json:"lightsOn,omitempty"` // nil = not declared
	Overrides  Overrides `json:"overrides"`

	// digest is the SHA-256 of the contract's canonical JSON, set by the Parser
	// after the contract passed the schema. Compile skips its own schema pass
	// when a contract still has the same digest: any later change to a field
	// changes the JSON, so a mutated or hand-built contract is validated again.
	digest   [sha256.Size]byte
	digested bool
}

// Paths holds path patterns, anchored at the contract's directory.
type Paths struct {
	Writable  *[]string `json:"writable,omitempty"` // nil = absent; non-nil empty = declared empty
	ReadOnly  []string  `json:"readOnly,omitempty"`
	Forbidden []string  `json:"forbidden,omitempty"`
	Sensitive []string  `json:"sensitive,omitempty"`
	Generated *[]string `json:"generated,omitempty"` // override field: nil = absent
}

// Gates references existing CI gates.
type Gates struct {
	Verify          []Gate  `json:"verify,omitempty"`
	Union           []Gate  `json:"union,omitempty"`
	DarkMergeOracle *Oracle `json:"darkMergeOracle,omitempty"`
}

// GateRef identifies a CI check pinned to a workflow revision (CON-4).
type GateRef struct {
	ProducerID       string     `json:"producerId"`
	WorkflowID       WorkflowID `json:"workflowId"`
	WorkflowRevision string     `json:"workflowRevision"`
	CheckID          string     `json:"checkId"`
}

// GateKey is a gate's identity without its revision.
type GateKey struct {
	ProducerID string
	WorkflowID WorkflowID
	CheckID    string
}

// Key returns the gate identity without the pinned revision.
func (r GateRef) Key() GateKey {
	return GateKey{ProducerID: r.ProducerID, WorkflowID: r.WorkflowID, CheckID: r.CheckID}
}

// Gate is a reference to an existing CI gate. Name is display only.
type Gate struct {
	Name string `json:"name"`
	GateRef
	Mandatory bool `json:"mandatory"`
}

// Oracle is the dark-merge oracle gate. It is always mandatory.
type Oracle struct {
	Name string `json:"name,omitempty"`
	GateRef
	Observables []Observable `json:"observables"`
	// CaseManifest pins the case manifest (PIP-13): the case IDs, fixture digests, boundaries and covered paths
	// the oracle must observe. Only the digest is identity.
	CaseManifest CaseManifest `json:"caseManifest"`
}

// CaseManifest pins the oracle's case manifest by digest. Path says where to read it, relative to the repo root.
// SHA256 is the lowercase hex SHA-256 of the file's bytes and is the only identity: changing the cases changes the
// digest, so it is a contract change that goes through activation.
type CaseManifest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Observable is something the dark-merge oracle compares.
type Observable string

// Observables the dark-merge oracle can compare.
const (
	ObservableResponses  Observable = "responses"
	ObservableReads      Observable = "reads"
	ObservableWrites     Observable = "writes"
	ObservableEvents     Observable = "events"
	ObservableQueuedJobs Observable = "queued-jobs"
)

// Agents lists reviewer agents.
type Agents struct {
	Verify []string `json:"verify,omitempty"`
}

// Overrides are values where the lowest level wins.
type Overrides struct {
	SwitchStaleDays     *int `json:"switchStaleDays,omitempty"`
	SwitchAbandonedDays *int `json:"switchAbandonedDays,omitempty"`
	ReviewBudgetLines   *int `json:"reviewBudgetLines,omitempty"`
}

// WorkflowID is a workflow identity. JSON accepts a positive integer, kept
// exactly and never via float64, or a string.
type WorkflowID string

// UnmarshalJSON accepts a JSON number of plain digits (no sign, fraction,
// exponent or leading zeros) or a JSON string.
func (w *WorkflowID) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return errors.New("workflowId: empty value")
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("workflowId: %w", err)
		}
		*w = WorkflowID(s)
		return nil
	}
	for i, c := range b {
		if c < '0' || c > '9' {
			return fmt.Errorf("workflowId: want a positive integer or a string, got %s", quote(string(b)))
		}
		if c == '0' && i == 0 {
			return errors.New("workflowId: integer must be positive without leading zeros")
		}
	}
	*w = WorkflowID(b)
	return nil
}
