// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package github_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/github"
)

const scope = `"installation":{"id":42},"repository":{"id":7}`

func TestParse(t *testing.T) { // NFR-5
	t.Parallel()
	sha := strings.Repeat("a", 40)
	type sub = forge.EventSubject
	tests := []struct {
		name, event, body string
		want              forge.EventHint
	}{
		{
			"issues", "issues", `{"action":"opened",` + scope + `,"issue":{"id":1001,"number":5}}`,
			forge.EventHint{Event: "issues", Action: "opened", Subject: sub{ID: "1001", Number: "5"}},
		},
		{
			"issue_comment", "issue_comment", `{"action":"created",` + scope + `,"issue":{"number":5},"comment":{"id":99}}`,
			forge.EventHint{Event: "issue_comment", Action: "created", Subject: sub{ID: "99", Number: "5"}},
		},
		{
			"pull_request", "pull_request", `{"action":"synchronize",` + scope + `,"pull_request":{"id":3,"number":9}}`,
			forge.EventHint{Event: "pull_request", Action: "synchronize", Subject: sub{ID: "3", Number: "9"}},
		},
		{
			"pull_request_review", "pull_request_review", `{"action":"submitted",` + scope + `,"review":{"id":11},"pull_request":{"number":9}}`,
			forge.EventHint{Event: "pull_request_review", Action: "submitted", Subject: sub{ID: "11", Number: "9"}},
		},
		{
			"check_run", "check_run", `{"action":"completed",` + scope + `,"check_run":{"id":21,"head_sha":"` + sha + `"}}`,
			forge.EventHint{Event: "check_run", Action: "completed", Subject: sub{ID: "21", SHA: sha}},
		},
		{
			"check_suite", "check_suite", `{"action":"completed",` + scope + `,"check_suite":{"id":22,"head_sha":"` + sha + `"}}`,
			forge.EventHint{Event: "check_suite", Action: "completed", Subject: sub{ID: "22", SHA: sha}},
		},
		{
			"workflow_job", "workflow_job", `{"action":"completed",` + scope + `,"workflow_job":{"id":23,"head_sha":"` + sha + `"}}`,
			forge.EventHint{Event: "workflow_job", Action: "completed", Subject: sub{ID: "23", SHA: sha}},
		},
		{
			"workflow_run", "workflow_run", `{"action":"completed",` + scope + `,"workflow_run":{"id":24,"head_sha":"` + sha + `"}}`,
			forge.EventHint{Event: "workflow_run", Action: "completed", Subject: sub{ID: "24", SHA: sha}},
		},
		{
			"merge_group", "merge_group", `{"action":"checks_requested",` + scope + `,"merge_group":{"head_sha":"` + sha + `","head_ref":"refs/heads/gh-readonly-queue/main/pr-1"}}`,
			forge.EventHint{Event: "merge_group", Action: "checks_requested", Subject: sub{SHA: sha, Ref: "refs/heads/gh-readonly-queue/main/pr-1"}},
		},
		{
			"push", "push", `{` + scope + `,"ref":"refs/heads/main","after":"` + sha + `"}`,
			forge.EventHint{Event: "push", Subject: sub{Ref: "refs/heads/main", SHA: sha}},
		},
		{
			"sub_issues flat", "sub_issues", `{"action":"sub_issue_added",` + scope + `,"parent_issue_id":100,"sub_issue_id":200,"parent_issue_repo":{"id":7},"sub_issue_repo":{"id":7}}`,
			forge.EventHint{Event: "sub_issues", Action: "sub_issue_added", Subject: sub{ID: "200", Related: "100"}},
		},
		{
			"sub_issues nested", "sub_issues", `{"action":"sub_issue_added",` + scope + `,"parent_issue":{"id":100,"number":1},"sub_issue":{"id":200,"number":2},"parent_issue_repo":{"id":7},"sub_issue_repo":{"id":8}}`,
			forge.EventHint{Event: "sub_issues", Action: "sub_issue_added", RelatedRepositoryIDs: []string{"8"}, Subject: sub{ID: "200", Related: "100"}},
		},
		{
			"sub_issues in two other repos", "sub_issues", `{` + scope + `,"parent_issue_id":1,"sub_issue_id":2,"parent_issue_repo":{"id":9},"sub_issue_repo":{"id":8}}`,
			forge.EventHint{Event: "sub_issues", RelatedRepositoryIDs: []string{"8", "9"}, Subject: sub{ID: "2", Related: "1"}},
		},
		{
			"installation", "installation", `{"action":"deleted","installation":{"id":42},"repositories":[{"id":7},{"id":8}]}`,
			forge.EventHint{Event: "installation", Action: "deleted", RepositoryID: "-", Subject: sub{ID: "42", RepositoryIDs: []string{"7", "8"}}},
		},
		{
			"installation_repositories", "installation_repositories", `{"action":"removed","installation":{"id":42},"repositories_removed":[{"id":8}],"repositories_added":[{"id":9}]}`,
			forge.EventHint{Event: "installation_repositories", Action: "removed", RepositoryID: "-", Subject: sub{ID: "42", AddedRepositoryIDs: []string{"9"}, RemovedRepositoryIDs: []string{"8"}}},
		},
		{
			"member", "member", `{"action":"removed",` + scope + `,"member":{"id":5}}`,
			forge.EventHint{Event: "member", Action: "removed", Subject: sub{ID: "5"}},
		},
		{
			"membership", "membership", `{"action":"removed","installation":{"id":42},"member":{"id":5},"team":{"id":6}}`,
			forge.EventHint{Event: "membership", Action: "removed", RepositoryID: "-", Subject: sub{ID: "5", Related: "6"}},
		},
		{
			"repository", "repository", `{"action":"renamed",` + scope + `}`,
			forge.EventHint{Event: "repository", Action: "renamed", Subject: sub{ID: "7"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.want.InstallationID = "42"
			if tt.want.RepositoryID == "-" {
				tt.want.RepositoryID = "" // an installation-level event has no signed repository
			} else {
				tt.want.RepositoryID = "7"
			}
			got, err := github.Parse(tt.event, []byte(tt.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("hint mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseNoSubjectRejected(t *testing.T) { // NFR-5 negative
	t.Parallel()
	for _, event := range []string{
		"issues", "issue_comment", "pull_request", "pull_request_review", "check_run", "check_suite", "workflow_job",
		"workflow_run", "merge_group", "push", "sub_issues", "member", "membership",
	} {
		t.Run(event, func(t *testing.T) {
			t.Parallel()
			_, err := github.Parse(event, []byte(`{`+scope+`}`))
			if !errors.Is(err, forge.ErrMalformedEvent) {
				t.Fatalf("Parse error = %v, want ErrMalformedEvent", err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) { // NFR-5 negative
	t.Parallel()
	ref := func(r string) string { return `{` + scope + `,"ref":"` + r + `"}` }
	tests := []struct {
		name, event, body string
		want              error
	}{
		{"ping", "ping", `{}`, forge.ErrPing},
		{"unsupported event", "star", `{` + scope + `}`, forge.ErrUnsupportedEvent},
		{"missing repository", "issues", `{"installation":{"id":42},"issue":{"id":1}}`, forge.ErrMissingScope},
		{"missing installation", "issues", `{"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMissingScope},
		{"null installation id", "issues", `{"installation":{"id":null},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMissingScope},
		{"installation event missing installation", "installation", `{"action":"deleted"}`, forge.ErrMissingScope},
		{"not json", "issues", `not json`, forge.ErrMalformedEvent},
		{"not an object", "issues", `[1]`, forge.ErrMalformedEvent},
		{"trailing data", "issues", `{` + scope + `,"issue":{"id":1}} {}`, forge.ErrMalformedEvent},
		{"string installation id", "issues", `{"installation":{"id":"42"},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"fractional id", "issues", `{"installation":{"id":4.5},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"negative id", "issues", `{"installation":{"id":-4},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"21-digit id", "issues", `{"installation":{"id":123456789012345678901},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"duplicate key", "issues", `{"installation":{"id":42},"installation":{"id":43},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"wrongly cased key", "issues", `{"Installation":{"id":42},"repository":{"id":7},"issue":{"id":1}}`, forge.ErrMissingScope},
		{"action of 65 chars", "issues", `{"action":"` + strings.Repeat("a", 65) + `",` + scope + `,"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"uppercase action", "issues", `{"action":"Opened",` + scope + `,"issue":{"id":1}}`, forge.ErrMalformedEvent},
		{"uppercase sha", "check_run", `{` + scope + `,"check_run":{"id":1,"head_sha":"` + strings.Repeat("A", 40) + `"}}`, forge.ErrMalformedEvent},
		{"non hex sha", "check_run", `{` + scope + `,"check_run":{"id":1,"head_sha":"zz"}}`, forge.ErrMalformedEvent},
		{"sha of 65 chars", "check_run", `{` + scope + `,"check_run":{"id":1,"head_sha":"` + strings.Repeat("a", 65) + `"}}`, forge.ErrMalformedEvent},
		{"ref of 256 bytes", "push", ref("refs/heads/" + strings.Repeat("r", 256-len("refs/heads/"))), forge.ErrMalformedEvent},
		{"ref without refs/", "push", ref("heads/main"), forge.ErrMalformedEvent},
		{"ref with space", "push", ref("refs/heads/a b"), forge.ErrMalformedEvent},
		{"ref with control char", "push", ref(`refs/heads/a\u0001b`), forge.ErrMalformedEvent},
		{"ref with tilde", "push", ref("refs/heads/a~1"), forge.ErrMalformedEvent},
		{"ref with caret", "push", ref("refs/heads/a^"), forge.ErrMalformedEvent},
		{"ref with colon", "push", ref("refs/heads/a:b"), forge.ErrMalformedEvent},
		{"ref with question mark", "push", ref("refs/heads/a?"), forge.ErrMalformedEvent},
		{"ref with star", "push", ref("refs/heads/a*"), forge.ErrMalformedEvent},
		{"ref with bracket", "push", ref("refs/heads/a["), forge.ErrMalformedEvent},
		{"ref with backslash", "push", ref(`refs/heads/a\\b`), forge.ErrMalformedEvent},
		{"ref with dotdot", "push", ref("refs/heads/a..b"), forge.ErrMalformedEvent},
		{"ref with at-brace", "push", ref("refs/heads/a@{b"), forge.ErrMalformedEvent},
		{"ref with leading dash component", "push", ref("refs/heads/-x"), forge.ErrMalformedEvent},
		{"ref with trailing dot", "push", ref("refs/heads/a."), forge.ErrMalformedEvent},
		{"ref with .lock component", "push", ref("refs/heads/a.lock/b"), forge.ErrMalformedEvent},
		{"ref with double slash", "push", ref("refs/heads//a"), forge.ErrMalformedEvent},
		{"ref with DEL", "push", ref(`refs/heads/a\u007fb`), forge.ErrMalformedEvent},
		{"sub_issues sub issue without its repository", "sub_issues", `{` + scope + `,"parent_issue_id":1,"sub_issue_id":2,"parent_issue_repo":{"id":7}}`, forge.ErrMissingScope},
		{"sub_issues parent issue without its repository", "sub_issues", `{` + scope + `,"parent_issue_id":1,"sub_issue_id":2,"sub_issue_repo":{"id":7}}`, forge.ErrMissingScope},
		{"ref with trailing slash", "push", ref("refs/heads/a/"), forge.ErrMalformedEvent},
		{"ref with leading dot component", "push", ref("refs/heads/.a"), forge.ErrMalformedEvent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := github.Parse(tt.event, []byte(tt.body))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseBoundaries(t *testing.T) { // NFR-5
	t.Parallel()
	tests := []struct{ name, event, body string }{
		{"action of 64 chars", "issues", `{"action":"` + strings.Repeat("a", 64) + `",` + scope + `,"issue":{"id":1}}`},
		{"ref of 255 bytes", "push", `{` + scope + `,"ref":"refs/heads/` + strings.Repeat("r", 255-len("refs/heads/")) + `"}`},
		{"20-digit id", "issues", `{"installation":{"id":18446744073709551615},"repository":{"id":7},"issue":{"id":1}}`},
		{"sha of 64 chars", "check_run", `{` + scope + `,"check_run":{"id":1,"head_sha":"` + strings.Repeat("a", 64) + `"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := github.Parse(tt.event, []byte(tt.body)); err != nil {
				t.Fatalf("Parse: %v", err)
			}
		})
	}
}

func TestParseTruncatesLongRepositoryLists(t *testing.T) { // NFR-5
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"action":"added","installation":{"id":42},"repositories_added":[`)
	for i := range forge.MaxHintRepositories + 5 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":` + strconv.Itoa(i+1) + `}`)
	}
	b.WriteString(`]}`)
	h, err := github.Parse("installation_repositories", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Subject.AddedRepositoryIDs) != forge.MaxHintRepositories || !h.Subject.Truncated {
		t.Errorf("added = %d, truncated = %v", len(h.Subject.AddedRepositoryIDs), h.Subject.Truncated)
	}

	// The same cut applies to removed repositories.
	b.Reset()
	b.WriteString(`{"action":"removed","installation":{"id":42},"repositories_removed":[`)
	for i := range forge.MaxHintRepositories + 1 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":` + strconv.Itoa(i+1) + `}`)
	}
	b.WriteString(`]}`)
	h, err = github.Parse("installation_repositories", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Subject.RemovedRepositoryIDs) != forge.MaxHintRepositories || !h.Subject.Truncated {
		t.Errorf("removed = %d, truncated = %v", len(h.Subject.RemovedRepositoryIDs), h.Subject.Truncated)
	}
}
