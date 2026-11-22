// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forge_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/forge"
)

func TestRateLimitError(t *testing.T) { // INTG-1
	t.Parallel()
	err := fmt.Errorf("list: %w", &forge.RateLimitError{RetryAfter: 30 * time.Second})
	if !errors.Is(err, forge.ErrRateLimited) {
		t.Fatal("RateLimitError does not wrap ErrRateLimited")
	}
	var rl *forge.RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 30*time.Second {
		t.Fatalf("errors.As = %v, %+v", errors.As(err, &rl), rl)
	}
}

// Zero values must fail closed: nobody is a user, no edit state is original, and provenance nobody vouched for
// is incomplete (SEC-10, PIP-2).
func TestZeroValuesFailClosed(t *testing.T) { // SEC-10, PIP-2
	t.Parallel()
	var (
		actor  forge.Actor
		edit   forge.EditState
		prov   forge.Provenance
		review forge.Review
		commit forge.Commit
		rules  forge.BranchRules
	)
	if actor.Kind == forge.ActorUser || edit == forge.EditOriginal || prov == forge.ProvenanceComplete {
		t.Fatalf("zero values are not fail-closed: %v %v %v", actor.Kind, edit, prov)
	}
	if review.State == forge.ReviewApproved || review.Edit == forge.EditOriginal {
		t.Fatalf("a zero review reads as approved or original: %+v", review)
	}
	if rules.Enforcement != forge.EnforcementUnknown || rules.Enforcement.String() != "unknown" {
		t.Fatalf("zero rules claim an enforcement: %v", rules.Enforcement)
	}
	if commit.Verified || rules.Complete {
		t.Fatalf("a zero commit is verified or zero rules are complete: %+v %+v", commit, rules)
	}
}

func TestEnumStrings(t *testing.T) {
	t.Parallel()
	for got, want := range map[string]string{
		forge.EditEdited.String():             "edited",
		forge.EditUnknown.String():            "unknown",
		forge.ProvenanceIncomplete.String():   "incomplete",
		forge.FileModeChanged.String():        "mode_changed",
		forge.ActorApp.String():               "app",
		forge.CheckConclusion(99).String():    "unknown(99)",
		forge.QueueInGroup.String():           "in_group",
		forge.TypeLabel.String():              "label",
		forge.ReviewChangesRequested.String(): "changes_requested",
	} {
		if got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}
