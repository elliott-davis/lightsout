// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forge

import "errors"

// Webhook event errors. They carry no payload content, so a caller may map them to fixed responses.
var (
	// ErrPing means the delivery is the forge's connectivity check. Nothing should be recorded for it.
	ErrPing = errors.New("forge: ping event")
	// ErrUnsupportedEvent means the event type yields no hint. Nothing should be recorded for it.
	ErrUnsupportedEvent = errors.New("forge: unsupported event")
	// ErrMalformedEvent means the payload is not the JSON the event requires.
	ErrMalformedEvent = errors.New("forge: malformed event payload")
	// ErrMissingScope means a supported event lacks its installation or a required repository ID.
	ErrMissingScope = errors.New("forge: event lacks installation or repository")
)

// MaxHintRepositories bounds each repository list in an [EventSubject]. A longer list sets
// [EventSubject.Truncated].
const MaxHintRepositories = 256

// EventHint is what a verified webhook delivery says to re-read. It is a hint and never authority (NFR-5): it names
// no author, verdict or role. The event loop re-reads the authoritative forge objects, and authorization is always
// checked at execution time against current sources (SEC-10).
//
// Every ID is a decimal string. The signed installation and repositories are scope-checked at ingest, but the loop
// must scope-check every object it re-reads from a hint too, including the ones in [EventSubject].
type EventHint struct {
	Event  string `json:"event"`
	Action string `json:"action,omitempty"`
	// InstallationID is the signed installation.
	InstallationID string `json:"installation_id"`
	// RepositoryID is the signed repository. It is empty for events that have none (installation, membership).
	RepositoryID string `json:"repository_id,omitempty"`
	// RelatedRepositoryIDs are other repositories the payload names (a sub-issue's, a parent issue's). Each one
	// must be in scope, like RepositoryID.
	RelatedRepositoryIDs []string     `json:"related_repository_ids,omitempty"`
	Subject              EventSubject `json:"subject"`
}

// EventSubject identifies the object a delivery was about. Every field is a hint, and unused ones are empty.
type EventSubject struct {
	// ID is the object's numeric ID (an issue, comment, review, PR, check, run, member or repository).
	ID string `json:"id,omitempty"`
	// Number is the issue or pull request number.
	Number string `json:"number,omitempty"`
	// SHA is a head commit SHA.
	SHA string `json:"sha,omitempty"`
	// Ref is a git ref (push, merge_group).
	Ref string `json:"ref,omitempty"`
	// Related is a related object's ID: a parent issue or a team.
	Related string `json:"related,omitempty"`
	// RepositoryIDs lists the repositories an installation event names (installation created, deleted, suspended).
	// AddedRepositoryIDs and RemovedRepositoryIDs list repositories an installation gained or lost. All are
	// recorded as evidence only and are not scope-checked: a removed repository is no longer in scope, and scope
	// comes only from the install config, never from a payload.
	RepositoryIDs        []string `json:"repository_ids,omitempty"`
	AddedRepositoryIDs   []string `json:"added_repository_ids,omitempty"`
	RemovedRepositoryIDs []string `json:"removed_repository_ids,omitempty"`
	// Truncated means a repository list was cut at [MaxHintRepositories].
	Truncated bool `json:"truncated,omitempty"`
}

// ScopedRepositoryIDs lists every repository that must be in scope for the hint to be accepted.
func (h EventHint) ScopedRepositoryIDs() []string {
	var ids []string
	if h.RepositoryID != "" {
		ids = append(ids, h.RepositoryID)
	}
	return append(ids, h.RelatedRepositoryIDs...)
}

// EventParser extracts the hint for event from a verified payload. It returns [ErrPing], [ErrUnsupportedEvent],
// [ErrMalformedEvent] or [ErrMissingScope] (possibly wrapped), and never an error containing payload content.
type EventParser func(event string, body []byte) (EventHint, error)
