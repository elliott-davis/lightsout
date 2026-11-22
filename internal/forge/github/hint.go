// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package github extracts event hints from GitHub webhook payloads (NFR-5).
//
// A [forge.EventHint] says only "re-read X": which installation, repository and object a delivery was about. It
// is never authority. The event loop re-reads the authoritative forge objects before acting, so nothing here
// records an author, a verdict, a role or a comment body. The caller must have verified the payload's signature
// first.
//
// Parsing is strict: the payload is decoded with encoding/json/v2, which rejects duplicate object keys at any
// depth and matches keys case-sensitively, so a payload cannot show one ID to a lenient reader and another to us.
// It does not import go-github. The adapter that talks to the forge API will.
package github

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/forge"
)

// The hint is stored in a work item, so every string in it is bounded and shaped.
var (
	validAction = regexp.MustCompile(`^[a-z_]{0,64}$`)
	validSHA    = regexp.MustCompile(`^[0-9a-f]{0,64}$`)
)

const (
	maxRefBytes    = 255
	eventSubIssues = "sub_issues"
)

// id is a JSON unsigned integer (at most 20 digits) kept as a decimal string. A JSON string, fraction, negative
// number or 21-digit number fails to decode, and null or absence leaves it zero, which means "absent".
type id uint64

func (i id) String() string {
	if i == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(i), 10)
}

type obj struct {
	ID     id `json:"id"`
	Number id `json:"number"`
}

type repoObj struct {
	ID id `json:"id"`
}

type shaObj struct {
	ID      id     `json:"id"`
	HeadSHA string `json:"head_sha"`
	HeadRef string `json:"head_ref"`
}

type envelope struct {
	Action       string  `json:"action"`
	Installation repoObj `json:"installation"`
	Repository   repoObj `json:"repository"`

	Issue       obj    `json:"issue"`
	Comment     obj    `json:"comment"`
	PullRequest obj    `json:"pull_request"`
	Review      obj    `json:"review"`
	CheckRun    shaObj `json:"check_run"`
	CheckSuite  shaObj `json:"check_suite"`
	WorkflowJob shaObj `json:"workflow_job"`
	WorkflowRun shaObj `json:"workflow_run"`
	MergeGroup  shaObj `json:"merge_group"`
	Ref         string `json:"ref"`
	After       string `json:"after"`

	ParentIssueID   id      `json:"parent_issue_id"`
	SubIssueID      id      `json:"sub_issue_id"`
	ParentIssue     obj     `json:"parent_issue"`
	SubIssue        obj     `json:"sub_issue"`
	ParentIssueRepo repoObj `json:"parent_issue_repo"`
	SubIssueRepo    repoObj `json:"sub_issue_repo"`

	Member            repoObj   `json:"member"`
	Team              repoObj   `json:"team"`
	Repositories      []repoObj `json:"repositories"`
	RepositoriesAdded []repoObj `json:"repositories_added"`
	RepositoriesGone  []repoObj `json:"repositories_removed"`
}

// plan says what an event must carry and how to read its subject.
type plan struct {
	// repoless events (installation, installation_repositories, membership) have no signed repository, so they
	// are scope-checked by installation only.
	repoless bool
	subject  func(e *envelope) (forge.EventSubject, bool)
}

// planFor returns the plan for event, or ok=false if the event has no parser.
func planFor(event string) (plan, bool) {
	switch event {
	case "issues":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.Issue.ID.String(), Number: e.Issue.Number.String()}, e.Issue.ID != 0 || e.Issue.Number != 0
		}}, true
	case "issue_comment":
		// The issue may be a pull request. The comment ID is what the loop re-reads.
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.Comment.ID.String(), Number: e.Issue.Number.String()}, e.Comment.ID != 0
		}}, true
	case "pull_request":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.PullRequest.ID.String(), Number: e.PullRequest.Number.String()},
				e.PullRequest.ID != 0 || e.PullRequest.Number != 0
		}}, true
	case "pull_request_review":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.Review.ID.String(), Number: e.PullRequest.Number.String()}, e.Review.ID != 0
		}}, true
	case "check_run":
		return plan{subject: sha(func(e *envelope) shaObj { return e.CheckRun })}, true
	case "check_suite":
		return plan{subject: sha(func(e *envelope) shaObj { return e.CheckSuite })}, true
	case "workflow_job":
		return plan{subject: sha(func(e *envelope) shaObj { return e.WorkflowJob })}, true
	case "workflow_run":
		return plan{subject: sha(func(e *envelope) shaObj { return e.WorkflowRun })}, true
	case "merge_group":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{SHA: e.MergeGroup.HeadSHA, Ref: e.MergeGroup.HeadRef}, e.MergeGroup.HeadSHA != ""
		}}, true
	case "push":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{Ref: e.Ref, SHA: e.After}, e.Ref != ""
		}}, true
	case eventSubIssues:
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			sub, parent := e.SubIssueID, e.ParentIssueID
			if sub == 0 {
				sub = e.SubIssue.ID
			}
			if parent == 0 {
				parent = e.ParentIssue.ID
			}
			return forge.EventSubject{ID: sub.String(), Related: parent.String()}, sub != 0 || parent != 0
		}}, true
	// Revocation and membership events. They are hints to re-read what the installation can still do. Authorization
	// is always re-read at execution, regardless of what they say (SEC-10, NFR-5).
	case "installation":
		return plan{repoless: true, subject: func(e *envelope) (forge.EventSubject, bool) {
			s := forge.EventSubject{ID: e.Installation.ID.String()}
			s.RepositoryIDs, s.Truncated = repoIDs(e.Repositories)
			return s, true
		}}, true
	case "installation_repositories":
		return plan{repoless: true, subject: func(e *envelope) (forge.EventSubject, bool) {
			s := forge.EventSubject{ID: e.Installation.ID.String()}
			var t1, t2 bool
			s.AddedRepositoryIDs, t1 = repoIDs(e.RepositoriesAdded)
			s.RemovedRepositoryIDs, t2 = repoIDs(e.RepositoriesGone)
			s.Truncated = t1 || t2
			return s, true
		}}, true
	case "member":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.Member.ID.String()}, e.Member.ID != 0
		}}, true
	case "membership":
		return plan{repoless: true, subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.Member.ID.String(), Related: e.Team.ID.String()}, e.Member.ID != 0
		}}, true
	case "repository":
		return plan{subject: func(e *envelope) (forge.EventSubject, bool) {
			return forge.EventSubject{ID: e.Repository.ID.String()}, true
		}}, true
	}
	return plan{}, false
}

func sha(get func(e *envelope) shaObj) func(e *envelope) (forge.EventSubject, bool) {
	return func(e *envelope) (forge.EventSubject, bool) {
		o := get(e)
		return forge.EventSubject{ID: o.ID.String(), SHA: o.HeadSHA}, o.ID != 0
	}
}

// repoIDs lists the repository IDs, at most [forge.MaxHintRepositories] of them.
func repoIDs(rs []repoObj) (ids []string, truncated bool) {
	for _, r := range rs {
		if r.ID == 0 {
			continue
		}
		if len(ids) == forge.MaxHintRepositories {
			return ids, true
		}
		ids = append(ids, r.ID.String())
	}
	return ids, false
}

// Parse extracts the hint for event from a verified payload. It is a [forge.EventParser]. It returns
// [forge.ErrPing] for ping, [forge.ErrUnsupportedEvent] for an event without a parser, [forge.ErrMalformedEvent]
// for a payload that is not the expected JSON (including duplicate or wrongly cased keys), and
// [forge.ErrMissingScope] if the installation, or a required repository, is absent. The errors never contain
// payload content.
func Parse(event string, body []byte) (forge.EventHint, error) {
	if event == "ping" {
		return forge.EventHint{}, forge.ErrPing
	}
	p, ok := planFor(event)
	if !ok {
		return forge.EventHint{}, forge.ErrUnsupportedEvent
	}
	var e envelope
	// Invalid UTF-8 is allowed in strings we do not read (a comment body may hold anything). Every string we keep
	// is validated below.
	if err := json.Unmarshal(body, &e, jsontext.AllowInvalidUTF8(true)); err != nil {
		return forge.EventHint{}, forge.ErrMalformedEvent
	}
	if e.Installation.ID == 0 || (!p.repoless && e.Repository.ID == 0) {
		return forge.EventHint{}, forge.ErrMissingScope
	}
	s, ok := p.subject(&e)
	if !ok || !validAction.MatchString(e.Action) || !validRef(s.Ref) || !validSHA.MatchString(s.SHA) {
		return forge.EventHint{}, forge.ErrMalformedEvent
	}
	if event == eventSubIssues && !subIssueReposPresent(&e) {
		// A named sub-issue or parent issue without its repository would escape the scope check.
		return forge.EventHint{}, forge.ErrMissingScope
	}
	h := forge.EventHint{
		Event:          event,
		Action:         e.Action,
		InstallationID: e.Installation.ID.String(),
		RepositoryID:   e.Repository.ID.String(),
		Subject:        s,
	}
	if event == eventSubIssues {
		h.RelatedRepositoryIDs = relatedRepos(h.RepositoryID, e.SubIssueRepo.ID, e.ParentIssueRepo.ID)
	}
	return h, nil
}

// subIssueReposPresent reports whether every issue a sub_issues payload names comes with its repository.
func subIssueReposPresent(e *envelope) bool {
	sub, parent := e.SubIssueID, e.ParentIssueID
	if sub == 0 {
		sub = e.SubIssue.ID
	}
	if parent == 0 {
		parent = e.ParentIssue.ID
	}
	return (sub == 0 || e.SubIssueRepo.ID != 0) && (parent == 0 || e.ParentIssueRepo.ID != 0)
}

// relatedRepos lists the repositories other than the signed one that a sub_issues payload names.
func relatedRepos(signed string, ids ...id) []string {
	var out []string
	for _, i := range ids {
		s := i.String()
		if s != "" && s != signed && !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// validRef applies git check-ref-format's rules to a full ref, plus a length cap. The empty ref is allowed
// (events without one).
func validRef(ref string) bool {
	if ref == "" {
		return true
	}
	if len(ref) > maxRefBytes || !utf8.ValidString(ref) || !strings.HasPrefix(ref, "refs/") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") {
		return false
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") || ref == "@" {
		return false
	}
	for i := range len(ref) {
		switch c := ref[i]; {
		case c < 0x20, c == 0x7f, c == ' ', c == '~', c == '^', c == ':', c == '?', c == '*', c == '[', c == '\\':
			return false
		}
	}
	for comp := range strings.SplitSeq(ref, "/") {
		if comp == "" || strings.HasPrefix(comp, "-") || strings.HasPrefix(comp, ".") || strings.HasSuffix(comp, ".lock") {
			return false
		}
	}
	return true
}

var _ forge.EventParser = Parse
