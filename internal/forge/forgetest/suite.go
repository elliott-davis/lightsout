// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forgetest

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

const (
	firstFile     = "a.txt"
	evilApp       = "evil-app"
	featureBranch = "feature"
)

// Run runs the conformance suite. newHarness must return a fresh, empty forge for each call. Each subtest names
// the PRD requirement it checks. A subtest that needs an optional interface the harness lacks is skipped.
func Run(t *testing.T, newHarness func(t *testing.T) Harness) {
	t.Helper()
	suite := []struct {
		name string
		fn   func(*env)
	}{
		{"SEC-10_actor_login_changes_ID_is_stable", testActorRename},
		{"SEC-10_team_membership_removal_visible_next_read", testTeamMembership},
		{"SEC-10_revoked_actor_unknown_non_member_and_cannot_push", testRevocation},
		{"INTG-1_issue_by_node_ID_survives_transfer", testIssueTransfer},
		{"INTG-1_create_issue_idempotent_on_key", testCreateIssueIdempotent},
		{"INTG-1_sub_issues_idempotent_acyclic_and_moved", testSubIssues},
		{"INTG-1_set_issue_type_native_or_label_fallback", testSetIssueType},
		{"SEC-10_issue_edit_state_visible_on_reread", testIssueEditState},
		{"SEC-10_comment_edit_visible_and_delete_is_not_found", testCommentEditState},
		{"SEC-10_review_edit_and_dismiss_visible_on_reread", testReviewEditState},
		{"SEC-10_pull_request_head_follows_branch_review_stays_pinned", testPRHeadFollows},
		{"SEC-3_fork_pull_request_reports_head_repo", testForkPR},
		{"SEC-3_closed_and_merged_pull_requests_do_not_follow_their_branch", testClosedAndMergedDoNotFollow},
		{"SEC-10_comments_and_reviews_do_not_replay_across_repos", testCrossRepoReplay},
		{"SEC-10_review_validation", testReviewValidation},
		{"INTG-1_pull_request_is_an_issue_and_transfer_is_validated", testPullRequestIsAnIssue},
		{"SEC-2_push_refused_to_default_protected_and_malformed_refs", testPushDenials},
		{"SEC-3_push_only_to_the_assigned_change", testPushAssignment},
		{"SEC-3_push_refused_for_reviewer_identity", testPushReviewer},
		{"SEC-3_push_does_not_touch_other_changes_ref", testPushIsolation},
		{"SEC-2_pusher_cannot_merge_or_enqueue", testPusherCannotMerge},
		{"SEC-2_push_stale_parent_conflicts", testPushStaleParent},
		{"SEC-2_concurrent_pushes_one_wins", testPushConcurrent},
		{"INTG-1_push_applies_writes_and_deletes", testPushApplies},
		{"SEC-1_push_refuses_git_dir_and_malformed_changes", testPushInputs},
		{"SEC-1_push_refuses_workflows_and_denied_paths", testPushPolicy},
		{"SEC-1_push_is_judged_against_the_trusted_base", testPushTrustedBase},
		{"INTG-1_tree_requires_full_sha", testTreeFullSHA},
		{"SEC-1_symlink_in_any_component_refused", testTreeSymlinks},
		{"SEC-1_gitlink_cannot_be_opened", testTreeGitlink},
		{"INTG-1_tree_modes_and_case_collisions", testTreeModes},
		{"INTG-1_commit_tree_copies_content", testCommitTreeCopies},
		{"INTG-1_tree_limits_give_ErrTooLarge", testTreeLimits},
		{"INTG-1_compare_reports_all_change_kinds", testCompare},
		{"INTG-1_compare_is_against_the_merge_base", testCompareMergeBase},
		{"INTG-1_compare_uses_the_best_common_ancestor", testCompareBestBase},
		{"INTG-1_commits_returns_every_commit_oldest_first", testCommits},
		{"SEC-5_branch_rules_unknown_branch_and_exact_rules", testBranchRules},
		{"CON-4_foreign_app_same_name_keeps_producer", testCheckForeignProducer},
		{"PIP-2_incomplete_provenance_stays_incomplete", testIncompleteProvenance},
		{"PIP-2_complete_provenance_needs_every_field", testCompleteNeedsFields},
		{"PIP-2_matrix_rerun_supersedes_only_its_own_leg", testSuperseded},
		{"PIP-2_supersession_is_independent_of_add_order", testSupersededOutOfOrder},
		{"PIP-2_later_attempt_without_job_id_still_supersedes", testSupersededWithoutJobID},
		{"CON-4_created_check_run_producer_is_factory_app", testCreateCheckRunProducer},
		{"CON-4_check_run_needs_real_commit_and_conclusion", testCheckRunInputs},
		{"CON-4_cannot_update_foreign_check_run", testUpdateForeignCheckRun},
		{"INTG-1_enqueue_stale_head_conflicts", testEnqueueStale},
		{"INTG-1_enqueue_refuses_merged_pull_request", testEnqueueMerged},
		{"INTG-1_push_to_queued_pull_request_removes_it", testPushRemovesFromQueue},
		{"INTG-1_dequeue_grouped_pull_request_fails_group", testDequeue},
		{"INTG-1_group_candidate_is_a_readable_commit", testGroupCandidate},
		{"INTG-1_eject_member_keeps_prefix_and_rebuilds_suffix", testEject},
		{"INTG-1_record_merge_is_validated_and_moves_base", testRecordMerge},
		{"INTG-1_record_merge_settles_the_group", testRecordMergeSettlesGroup},
		{"INTG-1_moving_the_base_fails_active_groups", testBaseMoveFailsGroups},
		{"INTG-1_retarget_removes_pull_request_from_queue", testRetarget},
		{"INTG-1_queue_refuses_drafts_closed_prs_and_mixed_bases", testQueueValidation},
		{"INTG-1_observed_merges_after_record", testObservedMerges},
		{"INTG-1_record_merge_is_consistent_with_the_repo", testRecordMergeConsistency},
		{"INTG-1_group_refs_follow_the_group_and_siblings_fail", testGroupLifecycle},
		{"INTG-1_group_on_a_non_default_base", testGroupOnOtherBase},
		{"INTG-1_merge_base_ignores_dominated_ancestors_whatever_their_order", testCompareBestBaseSortsFirst},
		{"INTG-1_undeclared_rename_is_removed_plus_added", testUndeclaredRenameIsRemovedPlusAdded},
		{"INTG-1_transferred_child_loses_its_parent", testTransferChildClearsParent},
		{"PIP-2_supersession_is_per_producer_and_workflow", testSupersessionIsPerProducer},
		{"CON-4_conclusion_only_when_completed", testCheckRunConclusionNeedsCompletion},
		{"INTG-1_close_draft_and_ref_validation", testPullRequestStateChanges},
	}
	for _, op := range []string{"ListComments", "ListReviews", "Compare", "Commits", "ListJobExecutions", "Tree"} {
		suite = append(suite, struct {
			name string
			fn   func(*env)
		}{"INTG-1_truncated_" + op + "_is_ErrIncomplete", incompleteCase(op)})
	}
	for _, tt := range suite {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.fn(newEnv(t, newHarness(t)))
		})
	}
}

// env is a harness with one repo ("main" holds an empty tree) and a user.
type env struct {
	t      *testing.T
	h      Harness
	repo   forge.RepoID
	main   string // full ref
	base   string // SHA of main
	author forge.Actor
	coder  forge.Actor // the identity every push test assigns changes to, never the factory's own
}

// allowAll is a Deny that protects nothing, for tests that are not about protected paths.
func allowAll(string) bool { return false }

// canonPath folds a path the way a control plane's protected matching must: case, and trailing dots and spaces
// on each segment.
func canonPath(p string) string {
	segs := strings.Split(strings.ToLower(p), "/")
	for i, s := range segs {
		segs[i] = strings.TrimRight(s, ". ")
	}
	return strings.Join(segs, "/")
}

// denyProtected is a Deny for the factory-protected paths of these tests, which canonicalizes its input.
func denyProtected(p string) bool {
	c := canonPath(p)
	return strings.HasPrefix(c, ".github/actions/") || c == "codeowners"
}

func (e *env) ctx() context.Context { return e.t.Context() }

func newEnv(t *testing.T, h Harness) *env {
	t.Helper()
	e := &env{t: t, h: h}
	e.repo = try(h.AddRepo(e.ctx(), "app", true)).get(t)
	e.main = try(h.DefaultBranch(e.ctx(), e.repo)).get(t)
	e.base = try(h.ResolveRef(e.ctx(), e.repo, e.main)).get(t)
	e.author = try(h.AddActor(e.ctx(), "alice", forge.ActorUser)).get(t)
	e.coder = try(h.AddActor(e.ctx(), "coder", forge.ActorBot)).get(t)
	return e
}

// result pairs a value with its error, so call sites can write try(h.Method(args)).get(t): Go cannot pass a
// multi-value call and t to one helper.
type result[T any] struct {
	v   T
	err error
}

func try[T any](v T, err error) result[T] { return result[T]{v, err} }

func (r result[T]) get(t *testing.T) T {
	t.Helper()
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.v
}

// need returns the harness as optional interface I, or skips the subtest.
func need[I any](e *env) I {
	e.t.Helper()
	i, ok := any(e.h).(I)
	if !ok {
		e.t.Skipf("harness does not implement %T", new(I))
	}
	return i
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func blob(p, data string) gittree.Entry {
	return gittree.Entry{Path: p, Mode: gittree.ModeBlob, Data: []byte(data)}
}

// commit stores a commit on top of parent with the entries and returns its SHA.
func (e *env) commit(parent, msg string, entries ...gittree.Entry) string {
	e.t.Helper()
	var parents []string
	if parent != "" {
		parents = []string{parent}
	}
	return try(e.h.CommitTree(e.ctx(), e.repo, parents, msg, entries)).get(e.t)
}

func (e *env) newIssue(title, key string) forge.Issue {
	e.t.Helper()
	return try(e.h.CreateIssue(e.ctx(), forge.NewIssue{Repo: e.repo, Title: title}, key)).get(e.t)
}

// pusher assigns change changeID to principal and binds a pusher to its ref.
func (e *env) pusher(principal forge.Actor, changeID string) forge.BranchPusher {
	e.t.Helper()
	return e.pusherWith(principal, changeID, forge.PushPolicy{Deny: allowAll})
}

func (e *env) pusherWith(principal forge.Actor, changeID string, policy forge.PushPolicy) forge.BranchPusher {
	e.t.Helper()
	return e.pusherAt(principal, changeID, e.base, policy)
}

// pusherAt assigns change changeID to principal on the trusted base and binds a pusher to its ref.
func (e *env) pusherAt(principal forge.Actor, changeID, base string, policy forge.PushPolicy) forge.BranchPusher {
	e.t.Helper()
	check(e.t, e.h.AssignChange(e.ctx(), e.repo, changeID, principal, base))
	return try(e.h.Pusher(e.ctx(), principal, e.repo, "refs/heads/factory/"+changeID, policy)).get(e.t)
}

func (e *env) resolve(ref string) (string, error) {
	return e.h.ResolveRef(e.ctx(), e.repo, ref)
}

func change(path, data string) forge.Change {
	return forge.Change{Message: "change " + path, Writes: []forge.FileWrite{{Path: path, Data: []byte(data)}}}
}

// ---- identity ----

func testActorRename(e *env) {
	t := e.t
	ids := need[Identities](e)
	before := try(e.h.GetActor(e.ctx(), e.author.ID)).get(t)
	check(t, ids.RenameActor(e.ctx(), e.author.ID, "alice-renamed"))
	after := try(e.h.GetActor(e.ctx(), e.author.ID)).get(t)
	if after.ID != before.ID || after.Login != "alice-renamed" || before.Login == after.Login {
		t.Fatalf("before = %+v, after = %+v: want same ID, new login", before, after)
	}
	_, err := e.h.GetActor(e.ctx(), "no-such-actor")
	wantErr(t, err, forge.ErrNotFound)
}

func testTeamMembership(e *env) {
	t := e.t
	ids := need[Identities](e)
	check(t, ids.AddTeamMember(e.ctx(), "acme", "owners", e.author.ID))
	if !try(e.h.IsTeamMember(e.ctx(), "acme", "owners", e.author.ID)).get(t) {
		t.Fatal("member not seen")
	}
	// Org "acme/owners" with team "x" must not collide with org "acme" and team "owners/x".
	check(t, ids.AddTeamMember(e.ctx(), "acme/owners", "x", e.author.ID))
	if try(e.h.IsTeamMember(e.ctx(), "acme", "owners/x", e.author.ID)).get(t) {
		t.Fatal("team keys collide")
	}
	check(t, ids.RemoveTeamMember(e.ctx(), "acme", "owners", e.author.ID))
	if try(e.h.IsTeamMember(e.ctx(), "acme", "owners", e.author.ID)).get(t) {
		t.Fatal("removed member still seen on the next read")
	}
}

func testRevocation(e *env) {
	t := e.t
	ids := need[Identities](e)
	coder := e.coder
	check(t, ids.AddTeamMember(e.ctx(), "acme", "owners", coder.ID))
	p := e.pusher(coder, "c1")
	check(t, ids.RevokeActor(e.ctx(), coder.ID))
	_, err := e.h.GetActor(e.ctx(), coder.ID)
	wantErr(t, err, forge.ErrNotFound)
	if try(e.h.IsTeamMember(e.ctx(), "acme", "owners", coder.ID)).get(t) {
		t.Fatal("revoked actor is still a team member")
	}
	_, err = p.Push(e.ctx(), e.base, change("a.txt", "1"))
	wantErr(t, err, forge.ErrForbidden)
	_, err = e.h.Pusher(e.ctx(), coder, e.repo, "refs/heads/factory/c1", forge.PushPolicy{Deny: allowAll})
	wantErr(t, err, forge.ErrForbidden)
}

// ---- issues ----

func testIssueTransfer(e *env) {
	t := e.t
	other := try(e.h.AddRepo(e.ctx(), "other", true)).get(t)
	i := e.newIssue("move me", "k")
	moved := try(e.h.TransferIssue(e.ctx(), e.repo, i.Number, other)).get(t)
	got := try(e.h.GetIssueByNodeID(e.ctx(), i.NodeID)).get(t)
	if got.NodeID != i.NodeID || got.Repo != other || got.TransferredFrom != e.repo || got.Number != moved.Number {
		t.Fatalf("after transfer = %+v (moved %+v)", got, moved)
	}
	_, err := e.h.GetIssue(e.ctx(), e.repo, i.Number)
	wantErr(t, err, forge.ErrNotFound)
}

func testCreateIssueIdempotent(e *env) {
	t := e.t
	a := e.newIssue("one", "same-key")
	b := e.newIssue("one retried", "same-key")
	c := e.newIssue("two", "other-key")
	if a.Number != b.Number || a.NodeID != b.NodeID {
		t.Fatalf("same key made two issues: %+v, %+v", a, b)
	}
	if c.Number == a.Number {
		t.Fatal("a different key returned the same issue")
	}
	if a.Author.ID != e.h.FactoryActor().ID {
		t.Fatalf("author = %+v, want the factory identity", a.Author)
	}
	// Keys are per repo: the same key in another repo is a new issue.
	other := try(e.h.AddRepo(e.ctx(), "other", true)).get(t)
	inOther := try(e.h.CreateIssue(e.ctx(), forge.NewIssue{Repo: other, Title: "one"}, "same-key")).get(t)
	if inOther.Repo != other || inOther.NodeID == a.NodeID {
		t.Fatalf("the same key in another repo returned %+v", inOther)
	}
	// After a transfer a retry in the original repo returns either the transferred issue (wherever it lives now) or
	// a new issue there. An adapter emulates keys with a repo-scoped marker, so it may do the second.
	try(e.h.TransferIssue(e.ctx(), e.repo, a.Number, other)).get(t)
	again := e.newIssue("one retried after transfer", "same-key")
	if again.NodeID != a.NodeID && (again.Repo != e.repo || again.TransferredFrom != "") {
		t.Fatalf("retry after transfer = %+v, want the transferred issue or a new issue in the original repo", again)
	}
}

func testSubIssues(e *env) {
	t := e.t
	p1, p2, child := e.newIssue("p1", "p1"), e.newIssue("p2", "p2"), e.newIssue("child", "c")
	check(t, e.h.AddSubIssue(e.ctx(), e.repo, p1.Number, child.Number))
	check(t, e.h.AddSubIssue(e.ctx(), e.repo, p1.Number, child.Number))
	if got := try(e.h.GetIssue(e.ctx(), e.repo, child.Number)).get(t); got.Parent != p1.Number {
		t.Fatalf("child parent = %d, want %d", got.Parent, p1.Number)
	}
	if subs := try(e.h.ListSubIssues(e.ctx(), e.repo, p1.Number)).get(t); len(subs) != 1 || subs[0].Number != child.Number {
		t.Fatalf("ListSubIssues = %+v", subs)
	}
	// Re-parenting moves the link.
	check(t, e.h.AddSubIssue(e.ctx(), e.repo, p2.Number, child.Number))
	if subs := try(e.h.ListSubIssues(e.ctx(), e.repo, p1.Number)).get(t); len(subs) != 0 {
		t.Fatalf("old parent still lists %+v", subs)
	}
	if subs := try(e.h.ListSubIssues(e.ctx(), e.repo, p2.Number)).get(t); len(subs) != 1 {
		t.Fatalf("new parent lists %+v", subs)
	}
	wantErr(t, e.h.AddSubIssue(e.ctx(), e.repo, child.Number, child.Number), forge.ErrInvalid)
	wantErr(t, e.h.AddSubIssue(e.ctx(), e.repo, child.Number, p2.Number), forge.ErrInvalid) // cycle
	wantErr(t, e.h.AddSubIssue(e.ctx(), e.repo, p2.Number, 9999), forge.ErrNotFound)
	wantErr(t, e.h.AddSubIssue(e.ctx(), e.repo, 9999, p2.Number), forge.ErrNotFound)
	// A transfer removes the links in both directions.
	other := try(e.h.AddRepo(e.ctx(), "other", true)).get(t)
	try(e.h.TransferIssue(e.ctx(), e.repo, p2.Number, other)).get(t)
	if got := try(e.h.GetIssue(e.ctx(), e.repo, child.Number)).get(t); got.Parent != 0 {
		t.Fatalf("child of a transferred parent has Parent = %d", got.Parent)
	}
}

func testSetIssueType(e *env) {
	t := e.t
	native := e.newIssue("native", "n")
	if mech := try(e.h.SetIssueType(e.ctx(), e.repo, native.Number, "bug")).get(t); mech != forge.TypeNative {
		t.Fatalf("mechanism = %v, want native", mech)
	}
	if got := try(e.h.GetIssue(e.ctx(), e.repo, native.Number)).get(t); got.Type != "bug" {
		t.Fatalf("type = %q", got.Type)
	}
	plain := try(e.h.AddRepo(e.ctx(), "plain", false)).get(t)
	i := try(e.h.CreateIssue(e.ctx(), forge.NewIssue{Repo: plain, Title: "label"}, "l")).get(t)
	if mech := try(e.h.SetIssueType(e.ctx(), plain, i.Number, "bug")).get(t); mech != forge.TypeLabel {
		t.Fatalf("mechanism = %v, want label", mech)
	}
	got := try(e.h.GetIssue(e.ctx(), plain, i.Number)).get(t)
	if diff := cmp.Diff([]string{"type:bug"}, got.Labels); diff != "" {
		t.Fatalf("labels (-want +got):\n%s", diff)
	}
	// CreateIssue with a type on a repo without native types applies the same fallback.
	typed := try(e.h.CreateIssue(e.ctx(), forge.NewIssue{Repo: plain, Title: "typed", Type: featureBranch}, "t")).get(t)
	if typed.Type != "" || !slices.Contains(typed.Labels, "type:feature") {
		t.Fatalf("typed issue on a repo without issue types = %+v", typed)
	}
}

// ---- edit state ----

func testIssueEditState(e *env) {
	t := e.t
	ed := need[Editor](e)
	human := try(e.h.AddIssue(e.ctx(), e.repo, e.author, "from a human", "approve the plan")).get(t)
	if human.Author.ID != e.author.ID || human.Edit != forge.EditOriginal {
		t.Fatalf("new issue = %+v", human)
	}
	check(t, ed.EditIssue(e.ctx(), e.repo, human.Number, "reject the plan"))
	got := try(e.h.GetIssue(e.ctx(), e.repo, human.Number)).get(t)
	if got.Edit != forge.EditEdited || got.Body != "reject the plan" {
		t.Fatalf("re-read after edit = %+v", got)
	}
	own := e.newIssue("factory issue", "f")
	check(t, e.h.UpdateIssueBody(e.ctx(), e.repo, own.Number, "new body"))
	if got := try(e.h.GetIssue(e.ctx(), e.repo, own.Number)).get(t); got.Edit != forge.EditEdited {
		t.Fatalf("issue edited by the factory reads %v", got.Edit)
	}
}

func testCommentEditState(e *env) {
	t := e.t
	ed := need[Editor](e)
	i := e.newIssue("c", "c")
	edited := try(e.h.AddComment(e.ctx(), e.repo, i.Number, e.author, "approve")).get(t)
	deleted := try(e.h.AddComment(e.ctx(), e.repo, i.Number, e.author, "approve too")).get(t)
	if edited.Edit != forge.EditOriginal {
		t.Fatalf("new comment edit state = %v", edited.Edit)
	}
	check(t, ed.EditComment(e.ctx(), e.repo, edited.ID, "reject"))
	check(t, ed.DeleteComment(e.ctx(), e.repo, deleted.ID))
	if got := try(e.h.GetComment(e.ctx(), e.repo, edited.ID)).get(t); got.Edit != forge.EditEdited || got.Body != "reject" {
		t.Fatalf("edited comment = %+v", got)
	}
	_, err := e.h.GetComment(e.ctx(), e.repo, deleted.ID)
	wantErr(t, err, forge.ErrNotFound)
	list := try(e.h.ListComments(e.ctx(), e.repo, i.Number)).get(t)
	if len(list) != 1 || list[0].ID != edited.ID || list[0].Edit != forge.EditEdited {
		t.Fatalf("ListComments = %+v, want only the edited comment", list)
	}
	_, err = e.h.ListComments(e.ctx(), e.repo, 9999)
	wantErr(t, err, forge.ErrNotFound)
}

func (e *env) openPR(branch string) forge.PullRequest {
	e.t.Helper()
	head := e.commit(e.base, branch, blob(branch+".txt", branch))
	check(e.t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/"+branch, head))
	return try(e.h.AddPullRequest(e.ctx(), e.repo, e.author, e.repo, branch, e.main)).get(e.t)
}

func testReviewEditState(e *env) {
	t := e.t
	ed := need[Editor](e)
	pr := e.openPR("feature")
	reviewer := try(e.h.AddActor(e.ctx(), "bob", forge.ActorUser)).get(t)
	edited := try(e.h.AddReview(e.ctx(), e.repo, pr.Number, reviewer, pr.HeadSHA, forge.ReviewApproved)).get(t)
	dismissed := try(e.h.AddReview(e.ctx(), e.repo, pr.Number, reviewer, pr.HeadSHA, forge.ReviewApproved)).get(t)
	if edited.Edit != forge.EditOriginal || edited.State != forge.ReviewApproved {
		t.Fatalf("new review = %+v", edited)
	}
	check(t, ed.EditReview(e.ctx(), e.repo, pr.Number, edited.ID, "actually, hold on"))
	check(t, ed.DismissReview(e.ctx(), e.repo, pr.Number, dismissed.ID))
	got := try(e.h.GetReview(e.ctx(), e.repo, pr.Number, edited.ID)).get(t)
	if got.Edit != forge.EditEdited || got.Body != "actually, hold on" || got.State != forge.ReviewApproved || got.CommitSHA != pr.HeadSHA {
		t.Fatalf("edited review = %+v: only the body may change", got)
	}
	if got := try(e.h.GetReview(e.ctx(), e.repo, pr.Number, dismissed.ID)).get(t); got.State != forge.ReviewDismissed {
		t.Fatalf("dismissed review = %+v", got)
	}
	if n := len(try(e.h.ListReviews(e.ctx(), e.repo, pr.Number)).get(t)); n != 2 {
		t.Fatalf("ListReviews returned %d, want 2", n)
	}
	_, err := e.h.ListReviews(e.ctx(), e.repo, 9999)
	wantErr(t, err, forge.ErrNotFound)
}

// ---- pull requests ----

func testPRHeadFollows(e *env) {
	t := e.t
	pr := e.openPR("feature")
	x := pr.HeadSHA
	reviewer := try(e.h.AddActor(e.ctx(), "bob", forge.ActorUser)).get(t)
	rv := try(e.h.AddReview(e.ctx(), e.repo, pr.Number, reviewer, x, forge.ReviewApproved)).get(t)
	y := e.commit(x, "newer", blob("feature.txt", "v2"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/feature", y))
	if got := try(e.h.GetPullRequest(e.ctx(), e.repo, pr.Number)).get(t); got.HeadSHA != y {
		t.Fatalf("HeadSHA = %s after the branch moved to %s", got.HeadSHA, y)
	}
	if got := try(e.h.GetReview(e.ctx(), e.repo, pr.Number, rv.ID)).get(t); got.CommitSHA != x {
		t.Fatalf("review CommitSHA = %s, want it pinned to %s", got.CommitSHA, x)
	}
	_, err := e.h.Enqueue(e.ctx(), e.repo, pr.Number, x)
	wantErr(t, err, forge.ErrConflict)
	// A push to the head branch moves it the same way.
	coder := e.coder
	head := e.commit(e.base, "factory", blob("f.txt", "f"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/factory/p1", head))
	fpr := try(e.h.AddPullRequest(e.ctx(), e.repo, coder, e.repo, "factory/p1", e.main)).get(t)
	p := e.pusher(coder, "p1")
	pushed := try(p.Push(e.ctx(), head, change("f.txt", "f2"))).get(t)
	if got := try(e.h.GetPullRequest(e.ctx(), e.repo, fpr.Number)).get(t); got.HeadSHA != pushed {
		t.Fatalf("HeadSHA = %s after a push to %s", got.HeadSHA, pushed)
	}
}

func testForkPR(e *env) {
	t := e.t
	fork := try(e.h.ForkRepo(e.ctx(), e.repo, "fork")).get(t)
	head := try(e.h.CommitTree(e.ctx(), fork, []string{e.base}, "fork change", []gittree.Entry{blob("f.txt", "f")})).get(t)
	check(t, e.h.SetRef(e.ctx(), fork, "refs/heads/factory/x", head))
	pr := try(e.h.AddPullRequest(e.ctx(), e.repo, e.author, fork, "factory/x", e.main)).get(t)
	if pr.HeadRepo != fork || pr.Repo != e.repo || pr.HeadRef != "factory/x" || pr.HeadSHA != head {
		t.Fatalf("fork pull request = %+v", pr)
	}
	if _, err := e.h.Tree(e.ctx(), e.repo, pr.HeadSHA); err != nil {
		t.Fatalf("fork head is not readable in the base repo: %v", err)
	}
	// A push to a branch of the same name in the base repo does not move the fork's pull request.
	other := e.commit(e.base, "base repo factory/x", blob("x.txt", "x"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/factory/x", other))
	if got := try(e.h.GetPullRequest(e.ctx(), e.repo, pr.Number)).get(t); got.HeadSHA != head {
		t.Fatalf("fork PR head = %s after a base repo branch of the same name moved, want %s", got.HeadSHA, head)
	}
	// A head and base with no common history cannot be opened, as on GitHub.
	unrelated := try(e.h.AddRepo(e.ctx(), "unrelated", true)).get(t)
	unrelatedHead := try(e.h.CommitTree(e.ctx(), unrelated, nil, "root", []gittree.Entry{blob("u.txt", "u")})).get(t)
	check(t, e.h.SetRef(e.ctx(), unrelated, "refs/heads/u", unrelatedHead))
	_, err := e.h.AddPullRequest(e.ctx(), e.repo, e.author, unrelated, "u", e.main)
	wantErr(t, err, forge.ErrInvalid)
}

func testClosedAndMergedDoNotFollow(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	closed, merged := e.openPR("closed"), e.openPR("merged")
	check(t, qs.ClosePullRequest(e.ctx(), e.repo, closed.Number))
	check(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: merged.Number, HeadSHA: merged.HeadSHA, MergedCommit: merged.HeadSHA, MergedBy: e.author}))
	for _, pr := range []*forge.PullRequest{&closed, &merged} {
		moved := e.commit(pr.HeadSHA, "later", blob(pr.HeadRef+".txt", "later"))
		check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/"+pr.HeadRef, moved))
		if got := try(e.h.GetPullRequest(e.ctx(), e.repo, pr.Number)).get(t); got.HeadSHA != pr.HeadSHA {
			t.Errorf("%s PR head = %s after its branch moved, want it to stay at %s", got.State, got.HeadSHA, pr.HeadSHA)
		}
	}
}

func testCrossRepoReplay(e *env) {
	t := e.t
	other := try(e.h.AddRepo(e.ctx(), "other", true)).get(t)
	i := e.newIssue("c", "c")
	c := try(e.h.AddComment(e.ctx(), e.repo, i.Number, e.author, "approve")).get(t)
	_, err := e.h.GetComment(e.ctx(), other, c.ID)
	wantErr(t, err, forge.ErrNotFound)
	pr, pr2 := e.openPR("one"), e.openPR("two")
	rv := try(e.h.AddReview(e.ctx(), e.repo, pr.Number, try(e.h.AddActor(e.ctx(), "bob", forge.ActorUser)).get(t), pr.HeadSHA, forge.ReviewApproved)).get(t)
	_, err = e.h.GetReview(e.ctx(), e.repo, pr2.Number, rv.ID)
	wantErr(t, err, forge.ErrNotFound)
	_, err = e.h.GetReview(e.ctx(), other, pr.Number, rv.ID)
	wantErr(t, err, forge.ErrNotFound)
}

func testReviewValidation(e *env) {
	t := e.t
	ed := need[Editor](e)
	pr := e.openPR("feature")
	bob := try(e.h.AddActor(e.ctx(), "bob", forge.ActorUser)).get(t)
	// The PR author cannot approve their own pull request.
	_, err := e.h.AddReview(e.ctx(), e.repo, pr.Number, e.author, pr.HeadSHA, forge.ReviewApproved)
	wantErr(t, err, forge.ErrForbidden)
	// The reviewed commit must have been a head of this pull request.
	_, err = e.h.AddReview(e.ctx(), e.repo, pr.Number, bob, e.base, forge.ReviewApproved)
	wantErr(t, err, forge.ErrInvalid)
	_, err = e.h.AddReview(e.ctx(), e.repo, pr.Number, bob, strings.Repeat("7", 40), forge.ReviewApproved)
	wantErr(t, err, forge.ErrInvalid)
	// Only approved, changes requested and commented are submittable.
	for _, st := range []forge.ReviewState{forge.ReviewStateUnknown, forge.ReviewDismissed} {
		_, err = e.h.AddReview(e.ctx(), e.repo, pr.Number, bob, pr.HeadSHA, st)
		wantErr(t, err, forge.ErrInvalid)
	}
	// A commented review cannot be dismissed.
	commented := try(e.h.AddReview(e.ctx(), e.repo, pr.Number, bob, pr.HeadSHA, forge.ReviewCommented)).get(t)
	wantErr(t, ed.DismissReview(e.ctx(), e.repo, pr.Number, commented.ID), forge.ErrInvalid)
	// An old head stays reviewable after the branch moves.
	moved := e.commit(pr.HeadSHA, "moved", blob("feature.txt", "2"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/feature", moved))
	try(e.h.AddReview(e.ctx(), e.repo, pr.Number, bob, pr.HeadSHA, forge.ReviewApproved)).get(t)
}

func testPullRequestIsAnIssue(e *env) {
	t := e.t
	pr := e.openPR("feature")
	check(t, e.h.AddLabels(e.ctx(), e.repo, pr.Number, "needs-review"))
	if mech := try(e.h.SetIssueType(e.ctx(), e.repo, pr.Number, "feature")).get(t); mech != forge.TypeNative {
		t.Fatalf("mechanism = %v", mech)
	}
	got := try(e.h.GetIssue(e.ctx(), e.repo, pr.Number)).get(t)
	if got.Number != pr.Number || !slices.Contains(got.Labels, "needs-review") || got.Type != "feature" {
		t.Fatalf("issue view of a pull request = %+v", got)
	}
	other := try(e.h.AddRepo(e.ctx(), "other", true)).get(t)
	_, err := e.h.TransferIssue(e.ctx(), e.repo, pr.Number, other)
	wantErr(t, err, forge.ErrInvalid)
	i := e.newIssue("same repo", "s")
	_, err = e.h.TransferIssue(e.ctx(), e.repo, i.Number, e.repo)
	wantErr(t, err, forge.ErrInvalid)
}

// ---- pushes ----

func testPushDenials(e *env) {
	t := e.t
	bot := e.coder
	check(t, e.h.AssignChange(e.ctx(), e.repo, "ok", bot, e.base))
	for _, ref := range []string{
		e.main, "refs/heads/release", "refs/heads/factory", "refs/heads/factory/", "refs/heads/factory/a/b",
		"refs/heads/factory/../main", "refs/tags/factory/a", "factory/ok", "refs/heads/other/factory/ok",
		"refs/heads/factory/" + strings.Repeat("a", 101),
	} {
		if _, err := e.h.Pusher(e.ctx(), bot, e.repo, ref, forge.PushPolicy{Deny: allowAll}); !errors.Is(err, forge.ErrForbidden) {
			t.Errorf("Pusher(%q) error = %v, want ErrForbidden", ref, err)
		}
	}
	// A factory ref that someone protected is refused at push time. Only an existing branch can be protected.
	wantErr(t, e.h.ProtectBranch(e.ctx(), e.repo, "factory/locked"), forge.ErrNotFound)
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/factory/locked", e.base))
	check(t, e.h.ProtectBranch(e.ctx(), e.repo, "factory/locked"))
	p := e.pusher(bot, "locked")
	_, err := p.Push(e.ctx(), e.base, change("a.txt", "1"))
	wantErr(t, err, forge.ErrForbidden)
	if got := try(e.resolve("refs/heads/factory/locked")).get(t); got != e.base {
		t.Fatalf("protected ref moved to %s", got)
	}
	if got := try(e.resolve(e.main)).get(t); got != e.base {
		t.Fatalf("default branch moved to %s", got)
	}
}

func testPushAssignment(e *env) {
	t := e.t
	alice, mallory := e.author, try(e.h.AddActor(e.ctx(), "mallory", forge.ActorBot)).get(t)
	p := e.pusher(alice, "mine")
	// The factory identity merges: it is never a coder.
	wantErr(t, e.h.AssignChange(e.ctx(), e.repo, "factory-owned", e.h.FactoryActor(), e.base), forge.ErrForbidden)
	// A change assigned in one repo has no pusher in another.
	elsewhere := try(e.h.AddRepo(e.ctx(), "elsewhere", true)).get(t)
	_, err0 := e.h.Pusher(e.ctx(), alice, elsewhere, "refs/heads/factory/mine", forge.PushPolicy{Deny: allowAll})
	wantErr(t, err0, forge.ErrForbidden)
	first := try(p.Push(e.ctx(), e.base, change("a.txt", "1"))).get(t)
	ref := "refs/heads/factory/mine"
	// A second principal cannot bind to, or push to, someone else's change.
	_, err := e.h.Pusher(e.ctx(), mallory, e.repo, ref, forge.PushPolicy{Deny: allowAll})
	wantErr(t, err, forge.ErrForbidden)
	// A change nobody assigned has no pusher.
	_, err = e.h.Pusher(e.ctx(), alice, e.repo, "refs/heads/factory/unassigned", forge.PushPolicy{Deny: allowAll})
	wantErr(t, err, forge.ErrForbidden)
	// The same ID on another forge is a different principal.
	foreign := forge.Actor{Forge: "other-forge", ID: alice.ID, Login: alice.Login, Kind: alice.Kind}
	_, err = e.h.Pusher(e.ctx(), foreign, e.repo, ref, forge.PushPolicy{Deny: allowAll})
	wantErr(t, err, forge.ErrForbidden)
	// Reassigning the change takes the original pusher's right away.
	check(t, e.h.AssignChange(e.ctx(), e.repo, "mine", mallory, e.base))
	_, err = p.Push(e.ctx(), first, change("b.txt", "2"))
	wantErr(t, err, forge.ErrForbidden)
	if got := try(e.resolve(ref)).get(t); got != first {
		t.Fatalf("ref moved to %s after a denied push", got)
	}
}

func testPushReviewer(e *env) {
	t := e.t
	ids := need[Identities](e)
	reviewer := try(e.h.AddActor(e.ctx(), "reviewer", forge.ActorUser)).get(t)
	p := e.pusher(reviewer, "c1")
	check(t, ids.MarkReviewer(e.ctx(), reviewer.ID))
	_, err := p.Push(e.ctx(), e.base, change("a.txt", "1"))
	wantErr(t, err, forge.ErrForbidden)
	_, err = e.resolve("refs/heads/factory/c1")
	wantErr(t, err, forge.ErrNotFound)
}

func testPushIsolation(e *env) {
	t := e.t
	bot := e.coder
	a, b := e.pusher(bot, "change-a"), e.pusher(bot, "change-b")
	shaB := try(b.Push(e.ctx(), e.base, change("b.txt", "b"))).get(t)
	shaA := try(a.Push(e.ctx(), e.base, change("a.txt", "a"))).get(t)
	if got := try(e.resolve("refs/heads/factory/change-b")).get(t); got != shaB {
		t.Fatalf("change-b ref = %s, want %s: another change's push moved it", got, shaB)
	}
	_, err := a.Push(e.ctx(), shaB, change("a2.txt", "x"))
	wantErr(t, err, forge.ErrConflict)
	if got := try(e.resolve("refs/heads/factory/change-a")).get(t); got != shaA {
		t.Fatalf("change-a ref moved to %s", got)
	}
}

func testPusherCannotMerge(e *env) {
	p := e.pusher(e.coder, "c1")
	if _, ok := p.(forge.MergeQueue); ok {
		e.t.Fatal("a branch pusher implements forge.MergeQueue")
	}
}

func testPushStaleParent(e *env) {
	t := e.t
	p := e.pusher(e.coder, "c1")
	first := try(p.Push(e.ctx(), e.base, change("a.txt", "1"))).get(t)
	_, err := p.Push(e.ctx(), e.base, change("b.txt", "2"))
	wantErr(t, err, forge.ErrConflict)
	if got := try(e.resolve("refs/heads/factory/c1")).get(t); got != first {
		t.Fatalf("ref = %s after a stale push, want %s", got, first)
	}
	second := try(p.Push(e.ctx(), first, change("b.txt", "2"))).get(t)
	if second == first {
		t.Fatal("push did not make a new commit")
	}
	if _, err := p.Push(e.ctx(), strings.Repeat("0", 40), change("c.txt", "3")); err == nil {
		t.Fatal("push on an unknown parent succeeded")
	}
}

// raceOnce pushes n changes with the same parent at once and returns how many succeeded and the winner's SHA.
func (e *env) raceOnce(p forge.BranchPusher, parent string, n int) (int, string) {
	e.t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, n)
	shas := make([]string, n)
	for i := range n {
		wg.Go(func() {
			shas[i], errs[i] = p.Push(e.ctx(), parent, change(fmt.Sprintf("f%d.txt", i), "x"))
		})
	}
	wg.Wait()
	wins, winner := 0, ""
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
			winner = shas[i]
		case !errors.Is(err, forge.ErrConflict):
			e.t.Errorf("losing push error = %v, want ErrConflict", err)
		}
	}
	return wins, winner
}

func testPushConcurrent(e *env) {
	t := e.t
	p := e.pusher(e.coder, "race")
	// Creating the ref, then moving it: each round exactly one of the pushes with the same parent wins.
	parent := e.base
	for round := range 2 {
		wins, winner := e.raceOnce(p, parent, 8)
		if wins != 1 {
			t.Fatalf("round %d: %d pushes with the same parent succeeded, want exactly 1", round, wins)
		}
		parent = winner
	}
	if got := try(e.resolve("refs/heads/factory/race")).get(t); got != parent {
		t.Fatalf("ref = %s, want the last winner %s", got, parent)
	}
}

func testPushApplies(e *env) {
	t := e.t
	base := e.commit(e.base, "seed", blob("keep.txt", "k"), blob("drop.txt", "d"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/factory/seeded", base))
	p := e.pusher(e.coder, "seeded")
	sha := try(p.Push(e.ctx(), base, forge.Change{
		Message: "apply",
		Writes:  []forge.FileWrite{{Path: "dir/run.sh", Data: []byte("#!/bin/sh"), Executable: true}, {Path: "keep.txt", Data: []byte("k2")}},
		Deletes: []string{"drop.txt"},
	})).get(t)
	if got := string(try(e.h.ReadFile(e.ctx(), e.repo, sha, "keep.txt")).get(t)); got != "k2" {
		t.Fatalf("keep.txt = %q", got)
	}
	if _, err := e.h.ReadFile(e.ctx(), e.repo, sha, "drop.txt"); err == nil {
		t.Fatal("deleted file still readable")
	}
	tree := try(e.h.Tree(e.ctx(), e.repo, sha)).get(t)
	if fi := try(fs.Stat(tree, "dir/run.sh")).get(t); fi.Mode() != 0o755 {
		t.Fatalf("run.sh mode = %v", fi.Mode())
	}
	commits := try(e.h.Commits(e.ctx(), e.repo, base, sha)).get(t)
	if len(commits) != 1 || commits[0].Message != "apply" || commits[0].Verified {
		t.Fatalf("commits = %+v", commits)
	}
}

func testPushInputs(e *env) {
	t := e.t
	seed := e.commit(e.base, "seed", blob("keep.txt", "k"),
		gittree.Entry{Path: "link", Mode: gittree.ModeSymlink, Data: []byte("keep.txt")})
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/factory/in", seed))
	p := e.pusher(e.coder, "in")
	for _, bad := range []string{
		".git/config", "a/.GIT/hooks/x", ".Git", "sub/.git",
		".git ", ".git.", ".git...", ".git. .", "GIT~1/config", "git~1", "Git~1 ", "a/GIT~1./x",
		".g\u200cit/config", ".git\u200d", "\ufeff.git/config", ".gi\u202at", ".\u206agit", ".git::$INDEX_ALLOCATION/x",
	} {
		_, err := p.Push(e.ctx(), seed, change(bad, "x"))
		wantErr(t, err, forge.ErrForbidden)
		_, err = e.h.CommitTree(e.ctx(), e.repo, []string{seed}, "git", []gittree.Entry{blob(bad, "x")})
		wantErr(t, err, forge.ErrForbidden)
	}
	_, err := p.Push(e.ctx(), seed, forge.Change{Message: "empty"})
	wantErr(t, err, forge.ErrInvalid)
	_, err = p.Push(e.ctx(), seed, forge.Change{Writes: []forge.FileWrite{{Path: "a", Data: nil}, {Path: "a", Data: nil}}})
	wantErr(t, err, forge.ErrInvalid)
	_, err = p.Push(e.ctx(), seed, forge.Change{Deletes: []string{"missing.txt"}})
	wantErr(t, err, forge.ErrInvalid)
	_, err = p.Push(e.ctx(), seed, change("link/x.txt", "x"))
	wantErr(t, err, forge.ErrSymlink)
	_, err = p.Push(e.ctx(), seed, change("keep.txt/x", "x"))
	wantErr(t, err, forge.ErrInvalid)
	if got := try(e.resolve("refs/heads/factory/in")).get(t); got != seed {
		t.Fatalf("a refused push moved the ref to %s", got)
	}
}

// ---- trees ----

func testTreeFullSHA(e *env) {
	t := e.t
	sha := e.commit(e.base, "c", blob("a.txt", "a"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/feature", sha))
	for _, bad := range []string{sha[:7], sha[:39], "refs/heads/feature", "feature", "HEAD", strings.ToUpper(sha), ""} {
		if _, err := e.h.Tree(e.ctx(), e.repo, bad); err == nil {
			t.Errorf("Tree(%q) succeeded, want an error", bad)
		}
	}
	if _, err := e.h.Tree(e.ctx(), e.repo, sha); err != nil {
		t.Fatalf("Tree(full sha): %v", err)
	}
	if got := try(e.resolve("refs/heads/feature")).get(t); got != sha {
		t.Fatalf("ResolveRef = %s, want %s", got, sha)
	}
}

func testTreeSymlinks(e *env) {
	t := e.t
	sha := e.commit(e.base, "links",
		blob("real/CODEOWNERS", "* @alice"),
		gittree.Entry{Path: "dirlink", Mode: gittree.ModeSymlink, Data: []byte("real")},
		gittree.Entry{Path: ".factory.yaml", Mode: gittree.ModeSymlink, Data: []byte("real/CODEOWNERS")},
	)
	tree := try(e.h.Tree(e.ctx(), e.repo, sha)).get(t)
	for _, p := range []string{".factory.yaml", "dirlink", "dirlink/CODEOWNERS"} {
		if _, err := tree.Open(p); !errors.Is(err, forge.ErrSymlink) {
			t.Errorf("Open(%q) error = %v, want ErrSymlink", p, err)
		}
		if _, err := fs.ReadFile(tree, p); !errors.Is(err, forge.ErrSymlink) {
			t.Errorf("fs.ReadFile(%q) error = %v, want ErrSymlink", p, err)
		}
		if _, err := e.h.ReadFile(e.ctx(), e.repo, sha, p); !errors.Is(err, forge.ErrSymlink) {
			t.Errorf("ReadFile(%q) error = %v, want ErrSymlink", p, err)
		}
	}
	// The listing reports the symlink instead of hiding it, and its target can be read without following it.
	if fi := try(fs.Lstat(tree, ".factory.yaml")).get(t); fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("symlink mode = %v", fi.Mode())
	}
	if target := try(fs.ReadLink(tree, ".factory.yaml")).get(t); target != "real/CODEOWNERS" {
		t.Fatalf("ReadLink = %q", target)
	}
}

func testTreeGitlink(e *env) {
	t := e.t
	sha := e.commit(e.base, "sub", gittree.Entry{Path: "vendor", Mode: gittree.ModeGitlink, SHA: strings.Repeat("a", 40)}, blob("a.txt", "a"))
	tree := try(e.h.Tree(e.ctx(), e.repo, sha)).get(t)
	if _, err := tree.Open("vendor"); err == nil {
		t.Fatal("Open(gitlink) succeeded")
	}
	if _, err := tree.Open("vendor/file"); err == nil {
		t.Fatal("Open(path under gitlink) succeeded")
	}
	if fi := try(fs.Stat(tree, "vendor")).get(t); fi.Mode()&fs.ModeIrregular == 0 {
		t.Fatalf("gitlink mode = %v, want irregular", fi.Mode())
	}
}

func testTreeModes(e *env) {
	t := e.t
	sha := e.commit(e.base, "modes",
		gittree.Entry{Path: "bin/run", Mode: gittree.ModeExecutable, Data: []byte("#!/bin/sh")},
		blob("README", "upper"), blob("readme", "lower"), blob("Readme", "mixed"),
	)
	tree := try(e.h.Tree(e.ctx(), e.repo, sha)).get(t)
	if fi := try(fs.Stat(tree, "bin/run")).get(t); fi.Mode() != 0o755 || !fi.Mode().IsRegular() {
		t.Fatalf("executable mode = %v", fi.Mode())
	}
	for name, want := range map[string]string{"README": "upper", "readme": "lower", "Readme": "mixed"} {
		if got := string(try(fs.ReadFile(tree, name)).get(t)); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if ents := try(fs.ReadDir(tree, ".")).get(t); len(ents) != 4 {
		t.Fatalf("root has %d entries, want 4 (case-colliding names preserved)", len(ents))
	}
}

func testCommitTreeCopies(e *env) {
	t := e.t
	data := []byte("original")
	entries := []gittree.Entry{{Path: firstFile, Mode: gittree.ModeBlob, Data: data}}
	sha := try(e.h.CommitTree(e.ctx(), e.repo, []string{e.base}, "copy", entries)).get(t)
	data[0] = 'X'
	entries[0].Data = []byte("replaced")
	entries[0].Path = "b.txt"
	if got := string(try(e.h.ReadFile(e.ctx(), e.repo, sha, "a.txt")).get(t)); got != "original" {
		t.Fatalf("stored content changed after the input was mutated: %q", got)
	}
}

func testTreeLimits(e *env) {
	t := e.t
	ts := need[TreeSetup](e)
	big := e.commit(e.base, "big", blob("big.bin", "0123456789"), blob("small.txt", "ok"), blob("a/b/c/d.txt", "d"))
	small := e.commit(e.base, "small", blob("small.txt", "ok"), blob("other.txt", "ok"))
	check(t, ts.SetTreeLimits(e.ctx(), gittree.Limits{MaxFileBytes: 5, MaxEntries: 100}))
	// One oversized file fails the whole tree, so a partial listing can never be read as complete.
	if _, err := e.h.Tree(e.ctx(), e.repo, big); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("Tree(oversized file) error = %v, want ErrTooLarge", err)
	}
	if _, err := e.h.ReadFile(e.ctx(), e.repo, big, "big.bin"); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("ReadFile(oversized) error = %v, want ErrTooLarge", err)
	}
	if got := string(try(e.h.ReadFile(e.ctx(), e.repo, small, "small.txt")).get(t)); got != "ok" {
		t.Fatalf("small.txt = %q", got)
	}
	check(t, ts.SetTreeLimits(e.ctx(), gittree.Limits{MaxEntries: 1}))
	if _, err := e.h.Tree(e.ctx(), e.repo, small); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("Tree(too many entries) error = %v, want ErrTooLarge", err)
	}
	check(t, ts.SetTreeLimits(e.ctx(), gittree.Limits{MaxTotalBytes: 3}))
	if _, err := e.h.Tree(e.ctx(), e.repo, small); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("Tree(too many bytes) error = %v, want ErrTooLarge", err)
	}
}

// incompleteCase checks one truncated operation: it returns ErrIncomplete and a nil result, and every other
// operation still succeeds.
func incompleteCase(op string) func(*env) {
	return func(e *env) {
		t := e.t
		fi := need[FaultInjector](e)
		issue := e.newIssue("i", "i")
		pr := e.openPR("feature")
		head := pr.HeadSHA
		check(t, e.job(func(j *forge.JobExecution) { j.CandidateSHA = head }))
		calls := map[string]func() (isNil bool, err error){
			"ListComments": func() (bool, error) {
				v, err := e.h.ListComments(e.ctx(), e.repo, issue.Number)
				return v == nil, err
			},
			"ListReviews": func() (bool, error) {
				v, err := e.h.ListReviews(e.ctx(), e.repo, pr.Number)
				return v == nil, err
			},
			"Compare": func() (bool, error) {
				v, err := e.h.Compare(e.ctx(), e.repo, e.base, head)
				return v == nil, err
			},
			"Commits": func() (bool, error) {
				v, err := e.h.Commits(e.ctx(), e.repo, e.base, head)
				return v == nil, err
			},
			"ListJobExecutions": func() (bool, error) {
				v, err := e.h.ListJobExecutions(e.ctx(), e.repo, head)
				return v == nil, err
			},
			"Tree": func() (bool, error) {
				v, err := e.h.Tree(e.ctx(), e.repo, head)
				return v == nil, err
			},
		}
		check(t, fi.InjectIncomplete(e.ctx(), op))
		for name, call := range calls {
			isNil, err := call()
			if name == op {
				if !errors.Is(err, forge.ErrIncomplete) || !isNil {
					t.Errorf("%s = nil result %t, error %v; want a nil result and ErrIncomplete", name, isNil, err)
				}
			} else if err != nil {
				t.Errorf("%s failed because of a fault injected into %s: %v", name, op, err)
			}
		}
	}
}

// ---- diffs ----

func testCompare(e *env) {
	t := e.t
	ts := need[TreeSetup](e)
	exec := func(p, d string) gittree.Entry {
		return gittree.Entry{Path: p, Mode: gittree.ModeExecutable, Data: []byte(d)}
	}
	base := e.commit(e.base, "base",
		blob("same.txt", "s"), blob("mod.txt", "old"), blob("gone.txt", "g"), blob("old/name.txt", "moved"), blob("mode.sh", "#!"),
	)
	// same.txt is rewritten with the same bytes and a different stored SHA: it is not a modification.
	rewritten := blob("same.txt", "s")
	rewritten.SHA = strings.Repeat("e", 40)
	head := e.commit(base, "head",
		rewritten, blob("mod.txt", "new"), blob("added.txt", "a"), blob("new/name.txt", "moved"), exec("mode.sh", "#!"),
	)
	check(t, ts.DeclareRename(e.ctx(), e.repo, head, "old/name.txt", "new/name.txt"))
	got := try(e.h.Compare(e.ctx(), e.repo, base, head)).get(t)
	byPath := map[string]forge.ChangedFile{}
	for i := range got {
		byPath[got[i].Path] = got[i]
	}
	want := map[string]struct {
		status forge.FileStatus
		prev   string
	}{
		"added.txt": {forge.FileAdded, ""}, "gone.txt": {forge.FileRemoved, ""}, "mod.txt": {forge.FileModified, ""},
		"new/name.txt": {forge.FileRenamed, "old/name.txt"}, "mode.sh": {forge.FileModeChanged, ""},
	}
	if len(byPath) != len(want) {
		t.Fatalf("Compare = %+v, want %d files", got, len(want))
	}
	for p, w := range want {
		if c := byPath[p]; c.Status != w.status || c.PreviousPath != w.prev {
			t.Errorf("%s = %+v, want status %v previous %q", p, c, w.status, w.prev)
		}
	}
	if c := byPath["mode.sh"]; c.OldMode != 0o644 || c.NewMode != 0o755 {
		t.Errorf("mode.sh modes = %v -> %v", c.OldMode, c.NewMode)
	}
	if _, ok := byPath["old/name.txt"]; ok {
		t.Error("a renamed file is also reported at its old path")
	}
	// Without a declared rename the move is a removal plus an addition.
	got = try(e.h.Compare(e.ctx(), e.repo, head, base)).get(t)
	for i := range got {
		if got[i].Status == forge.FileRenamed {
			t.Fatalf("undeclared rename reported: %+v", got[i])
		}
	}
	_, err := e.h.Compare(e.ctx(), e.repo, base, strings.Repeat("1", 40))
	wantErr(t, err, forge.ErrNotFound)
}

func testCompareMergeBase(e *env) {
	t := e.t
	fork := e.commit(e.base, "fork point", blob("shared.txt", "s"))
	feature := e.commit(fork, "feature", blob("shared.txt", "s"), blob("feature.txt", "f"))
	// The base branch moved past the fork point.
	moved := e.commit(fork, "base moved", blob("shared.txt", "s"), blob("base-only.txt", "b"))
	got := try(e.h.Compare(e.ctx(), e.repo, moved, feature)).get(t)
	if len(got) != 1 || got[0].Path != "feature.txt" || got[0].Status != forge.FileAdded {
		t.Fatalf("Compare(moved base, feature) = %+v, want only feature.txt added", got)
	}
	// A root commit shares no ancestor.
	orphan := try(e.h.CommitTree(e.ctx(), e.repo, nil, "orphan", []gittree.Entry{blob("o.txt", "o")})).get(t)
	_, err := e.h.Compare(e.ctx(), e.repo, feature, orphan)
	wantErr(t, err, forge.ErrNotFound)
}

// testCompareBestBase uses a history where the first common ancestor found from the head is not the best one:
// C1 -> C2 -> B, and X merges F1 (off C1) with T1 (off C2) and puts policy.txt back as it was in C1. Both C1 and C2
// are common ancestors of B and X, C2 is the merge base, and so git diff B...X reports policy.txt as modified.
func testCompareBestBase(e *env) {
	t := e.t
	c1 := e.commit(e.base, "C1", blob("policy.txt", "A"))
	c2 := e.commit(c1, "C2", blob("policy.txt", "Z"))
	b := e.commit(c2, "B", blob("policy.txt", "Z"))
	f1 := e.commit(c1, "F1", blob("policy.txt", "A"), blob("f.txt", "f"))
	t1 := e.commit(c2, "T1", blob("policy.txt", "Z"), blob("t.txt", "t"))
	x := try(e.h.CommitTree(e.ctx(), e.repo, []string{f1, t1}, "X", []gittree.Entry{blob("policy.txt", "A"), blob("f.txt", "f"), blob("t.txt", "t")})).get(t)
	got := try(e.h.Compare(e.ctx(), e.repo, b, x)).get(t)
	byPath := map[string]forge.FileStatus{}
	for i := range got {
		byPath[got[i].Path] = got[i].Status
	}
	want := map[string]forge.FileStatus{"policy.txt": forge.FileModified, "f.txt": forge.FileAdded, "t.txt": forge.FileAdded}
	if diff := cmp.Diff(want, byPath); diff != "" {
		t.Fatalf("Compare(B, X) (-want +got):\n%s", diff)
	}
}

func testCommits(e *env) {
	t := e.t
	base := e.commit(e.base, "base", blob("a", "0"))
	c1 := e.commit(base, "first commit message\n\nbody", blob("a", "1"))
	side := e.commit(base, "side branch commit", blob("a", "0"), blob("s", "s"))
	merge := try(e.h.CommitTree(e.ctx(), e.repo, []string{c1, side}, "merge commit", []gittree.Entry{blob("a", "1"), blob("s", "s")})).get(t)
	head := e.commit(merge, "tip", blob("a", "1"), blob("s", "s"), blob("t", "t"))
	got := try(e.h.Commits(e.ctx(), e.repo, base, head)).get(t)
	msgs := map[string]bool{}
	pos := map[string]int{}
	for i := range got {
		msgs[got[i].Message] = true
		pos[got[i].SHA] = i
	}
	for _, m := range []string{"tip", "merge commit", "first commit message\n\nbody", "side branch commit"} {
		if !msgs[m] {
			t.Errorf("commit %q missing from %+v", m, got)
		}
	}
	if len(got) != 4 || got[len(got)-1].SHA != head {
		t.Fatalf("Commits = %d commits, last %s; want 4 ending at head", len(got), got[len(got)-1].SHA)
	}
	for i := range got {
		for _, p := range got[i].Parents {
			if j, in := pos[p]; in && j >= i {
				t.Errorf("commit %q comes before its parent", got[i].Message)
			}
		}
	}
	if n := len(try(e.h.Commits(e.ctx(), e.repo, head, head)).get(t)); n != 0 {
		t.Fatalf("Commits(head, head) = %d, want 0", n)
	}
	orphan := try(e.h.CommitTree(e.ctx(), e.repo, nil, "orphan", []gittree.Entry{blob("o", "o")})).get(t)
	_, err := e.h.Commits(e.ctx(), e.repo, head, orphan)
	wantErr(t, err, forge.ErrNotFound)
}

// ---- rules ----

func testBranchRules(e *env) {
	t := e.t
	_, err := e.h.BranchRules(e.ctx(), e.repo, "no-such-branch")
	wantErr(t, err, forge.ErrNotFound)
	// An existing branch with no rules reports an empty, complete set. Consumers must fail on an empty set.
	empty := try(e.h.BranchRules(e.ctx(), e.repo, "main")).get(t)
	if len(empty.RequiredChecks) != 0 || empty.MergeQueueRequired || !empty.Complete {
		t.Fatalf("rules on an unprotected branch = %+v", empty)
	}
	rules := forge.BranchRules{
		RequiredChecks:     []forge.RequiredCheck{{Context: "factory/verdict", AppID: e.h.FactoryAppID()}, {Context: "unpinned"}},
		MergeQueueRequired: true,
		BypassOther:        true,
		EnforceAdmins:      true,
		Enforcement:        forge.EnforcementEvaluate,
		Complete:           false,
	}
	check(t, e.h.SetBranchRules(e.ctx(), e.repo, "main", rules))
	for _, name := range []string{"main", "refs/heads/main"} {
		got := try(e.h.BranchRules(e.ctx(), e.repo, name)).get(t)
		if diff := cmp.Diff(rules, got); diff != "" {
			t.Errorf("BranchRules(%q) (-want +got):\n%s", name, diff)
		}
	}
}

// ---- checks ----

func (e *env) job(mut func(*forge.JobExecution)) error {
	e.t.Helper()
	je := forge.JobExecution{
		Repo: e.repo, CandidateSHA: e.base, Event: "merge_group", ProducerAppID: "actions-app", WorkflowRepo: e.repo,
		WorkflowPath: ".github/workflows/ci.yml", WorkflowCommit: strings.Repeat("c", 40), JobKey: "test",
		RunID: "10", RunAttempt: "1", JobID: "11", Conclusion: forge.ConclusionSuccess, Provenance: forge.ProvenanceComplete,
	}
	mut(&je)
	return e.h.AddJobExecution(e.ctx(), je)
}

func testCheckForeignProducer(e *env) {
	t := e.t
	own := try(e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: e.base, Name: "ci/test", Status: forge.CheckCompleted, Conclusion: forge.ConclusionSuccess})).get(t)
	foreign := try(e.h.AddCheckRun(e.ctx(), forge.CheckRun{
		Repo: e.repo, HeadSHA: e.base, Name: "ci/test", ProducerAppID: evilApp, Status: forge.CheckCompleted, Conclusion: forge.ConclusionSuccess,
	})).get(t)
	check(t, e.job(func(j *forge.JobExecution) { j.ProducerAppID = evilApp }))
	runs := try(e.h.ListCheckRuns(e.ctx(), e.repo, e.base)).get(t)
	if len(runs) != 2 {
		t.Fatalf("ListCheckRuns = %+v, want 2", runs)
	}
	producers := map[string]string{}
	for i := range runs {
		producers[runs[i].ID] = runs[i].ProducerAppID
	}
	if producers[own.ID] != e.h.FactoryAppID() || producers[foreign.ID] != evilApp {
		t.Fatalf("producers = %v: same-name runs must keep their true producer", producers)
	}
	jobs := try(e.h.ListJobExecutions(e.ctx(), e.repo, e.base)).get(t)
	if len(jobs) != 1 || jobs[0].ProducerAppID != evilApp {
		t.Fatalf("jobs = %+v", jobs)
	}
}

func testIncompleteProvenance(e *env) {
	t := e.t
	check(t, e.job(func(j *forge.JobExecution) {
		j.Provenance = forge.ProvenanceIncomplete
		j.WorkflowCommit = ""
	}))
	check(t, e.job(func(j *forge.JobExecution) {
		j.JobKey, j.RunID, j.JobID = "zero-value-provenance", "20", "21"
		j.Provenance = 0
	}))
	jobs := try(e.h.ListJobExecutions(e.ctx(), e.repo, e.base)).get(t)
	keys := map[string]bool{}
	for i := range jobs {
		j := &jobs[i]
		keys[j.JobKey] = true
		if j.Provenance != forge.ProvenanceIncomplete {
			t.Errorf("job %q provenance = %v, want incomplete", j.JobKey, j.Provenance)
		}
		if j.JobKey == "test" && j.WorkflowCommit != "" {
			t.Errorf("job %q had its missing workflow commit filled in: %q", j.JobKey, j.WorkflowCommit)
		}
	}
	if len(jobs) != 2 || !keys["test"] || !keys["zero-value-provenance"] {
		t.Fatalf("jobs = %+v, want both executions back", jobs)
	}
}

func testCompleteNeedsFields(e *env) {
	t := e.t
	for name, mut := range map[string]func(*forge.JobExecution){
		"producer":     func(j *forge.JobExecution) { j.ProducerAppID = "" },
		"repo":         func(j *forge.JobExecution) { j.WorkflowRepo = "" },
		"path":         func(j *forge.JobExecution) { j.WorkflowPath = "" },
		"commit":       func(j *forge.JobExecution) { j.WorkflowCommit = "" },
		"short commit": func(j *forge.JobExecution) { j.WorkflowCommit = "abc123" },
		"short sha":    func(j *forge.JobExecution) { j.CandidateSHA = "abc123" },
		"unknown sha":  func(j *forge.JobExecution) { j.CandidateSHA = strings.Repeat("8", 40) },
		"event":        func(j *forge.JobExecution) { j.Event = "" },
		"job key":      func(j *forge.JobExecution) { j.JobKey = "" },
		"run id":       func(j *forge.JobExecution) { j.RunID = "" },
		"attempt":      func(j *forge.JobExecution) { j.RunAttempt = "" },
		"text attempt": func(j *forge.JobExecution) { j.RunAttempt = "second" },
		"zero attempt": func(j *forge.JobExecution) { j.RunAttempt = "0" },
		"job id":       func(j *forge.JobExecution) { j.JobID = "" },
	} {
		wantErr(t, e.job(mut), forge.ErrInvalid)
		if jobs := try(e.h.ListJobExecutions(e.ctx(), e.repo, e.base)).get(t); len(jobs) != 0 {
			t.Fatalf("%s: a rejected record was stored: %+v", name, jobs)
		}
	}
}

func (e *env) jobs() map[string]forge.JobExecution {
	e.t.Helper()
	out := map[string]forge.JobExecution{}
	jobs := try(e.h.ListJobExecutions(e.ctx(), e.repo, e.base)).get(e.t)
	for i := range jobs {
		out[jobs[i].JobID] = jobs[i]
	}
	return out
}

func leg(name, attempt, id string, c forge.CheckConclusion) func(*forge.JobExecution) {
	return func(j *forge.JobExecution) { j.JobKey, j.RunAttempt, j.JobID, j.Conclusion = name, attempt, id, c }
}

func testSuperseded(e *env) {
	t := e.t
	// Attempt 1 fails on both legs of a matrix, then a re-run of the mac leg alone succeeds as attempt 2.
	check(t, e.job(leg("test (linux, 1.22)", "1", "11", forge.ConclusionFailure)))
	check(t, e.job(leg("test (mac, 1.22)", "1", "12", forge.ConclusionFailure)))
	check(t, e.job(leg("test (mac, 1.22)", "2", "13", forge.ConclusionSuccess)))
	got := e.jobs()
	if got["11"].SupersededBy != "" || got["11"].Conclusion != forge.ConclusionFailure {
		t.Errorf("linux attempt 1 = %+v, want failed and not superseded", got["11"])
	}
	if got["12"].SupersededBy != "13" || got["13"].SupersededBy != "" {
		t.Errorf("mac attempts = %+v, %+v: the first must be superseded by the re-run", got["12"], got["13"])
	}
}

func testSupersededOutOfOrder(e *env) {
	t := e.t
	check(t, e.job(leg("test", "2", "22", forge.ConclusionFailure)))
	check(t, e.job(leg("test", "1", "21", forge.ConclusionSuccess)))
	got := e.jobs()
	if got["21"].SupersededBy != "22" || got["22"].SupersededBy != "" {
		t.Fatalf("jobs = %+v: the older success, added second, must be marked superseded", got)
	}
}

func testSupersededWithoutJobID(e *env) {
	t := e.t
	check(t, e.job(leg("test", "1", "31", forge.ConclusionSuccess)))
	check(t, e.job(func(j *forge.JobExecution) {
		j.RunAttempt, j.JobID, j.Conclusion = "2", "", forge.ConclusionFailure
		j.Provenance = forge.ProvenanceIncomplete
	}))
	if got := e.jobs()["31"]; got.SupersededBy == "" {
		t.Fatalf("older attempt = %+v: a later attempt with no job ID must still supersede it", got)
	}
}

func testCreateCheckRunProducer(e *env) {
	t := e.t
	cr := try(e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: e.base, Name: "factory/verdict", Status: forge.CheckInProgress})).get(t)
	if cr.ProducerAppID != e.h.FactoryAppID() || cr.ProducerAppID == e.h.FactoryActor().ID {
		t.Fatalf("producer = %q, want the factory app ID %q, not the bot account ID %q", cr.ProducerAppID, e.h.FactoryAppID(), e.h.FactoryActor().ID)
	}
	done := try(e.h.UpdateCheckRun(e.ctx(), e.repo, cr.ID, forge.CheckCompleted, forge.ConclusionSuccess)).get(t)
	if done.ProducerAppID != cr.ProducerAppID || done.Conclusion != forge.ConclusionSuccess || done.Status != forge.CheckCompleted {
		t.Fatalf("updated run = %+v", done)
	}
}

func testCheckRunInputs(e *env) {
	t := e.t
	for _, sha := range []string{e.base[:7], strings.Repeat("9", 40), "main", ""} {
		_, err := e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: sha, Name: "x", Status: forge.CheckQueued})
		wantErr(t, err, forge.ErrNotFound)
	}
	_, err := e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: e.base, Name: "x", Status: forge.CheckCompleted})
	wantErr(t, err, forge.ErrInvalid)
	run := try(e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: e.base, Name: "x", Status: forge.CheckQueued})).get(t)
	_, err = e.h.UpdateCheckRun(e.ctx(), e.repo, run.ID, forge.CheckCompleted, forge.ConclusionNone)
	wantErr(t, err, forge.ErrInvalid)
}

func testUpdateForeignCheckRun(e *env) {
	t := e.t
	foreign := try(e.h.AddCheckRun(e.ctx(), forge.CheckRun{Repo: e.repo, HeadSHA: e.base, Name: "x", ProducerAppID: evilApp, Status: forge.CheckQueued})).get(t)
	_, err := e.h.UpdateCheckRun(e.ctx(), e.repo, foreign.ID, forge.CheckCompleted, forge.ConclusionSuccess)
	wantErr(t, err, forge.ErrForbidden)
	runs := try(e.h.ListCheckRuns(e.ctx(), e.repo, e.base)).get(t)
	if len(runs) != 1 || runs[0].Status != forge.CheckQueued || runs[0].Conclusion != forge.ConclusionNone {
		t.Fatalf("foreign run changed: %+v", runs)
	}
}

// ---- merge queue ----

func (e *env) enqueue(prs ...forge.PullRequest) {
	e.t.Helper()
	for i := range prs {
		try(e.h.Enqueue(e.ctx(), e.repo, prs[i].Number, prs[i].HeadSHA)).get(e.t)
	}
}

func (e *env) entry(pr int) forge.QueueEntry {
	e.t.Helper()
	for _, q := range try(e.h.QueueEntries(e.ctx(), e.repo)).get(e.t) {
		if q.PR == pr {
			return q
		}
	}
	e.t.Fatalf("no queue entry for PR %d", pr)
	return forge.QueueEntry{}
}

func testEnqueueStale(e *env) {
	t := e.t
	pr := e.openPR("feature")
	stale := pr.HeadSHA
	newHead := e.commit(pr.HeadSHA, "newer", blob("feature.txt", "v2"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/feature", newHead))
	_, err := e.h.Enqueue(e.ctx(), e.repo, pr.Number, stale)
	wantErr(t, err, forge.ErrConflict)
	if n := len(try(e.h.QueueEntries(e.ctx(), e.repo)).get(t)); n != 0 {
		t.Fatalf("a refused enqueue left %d queue entries", n)
	}
	entry := try(e.h.Enqueue(e.ctx(), e.repo, pr.Number, newHead)).get(t)
	if entry.State != forge.QueueQueued || entry.HeadSHA != newHead {
		t.Fatalf("entry = %+v", entry)
	}
	if n := len(try(e.h.MergeGroups(e.ctx(), e.repo)).get(t)); n != 0 {
		t.Fatalf("Enqueue started %d merge groups", n)
	}
}

func testEnqueueMerged(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	pr := e.openPR("feature")
	check(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: pr.Number, HeadSHA: pr.HeadSHA, MergedCommit: pr.HeadSHA, MergedBy: e.author}))
	_, err := e.h.Enqueue(e.ctx(), e.repo, pr.Number, pr.HeadSHA)
	wantErr(t, err, forge.ErrConflict)
}

func testPushRemovesFromQueue(e *env) {
	t := e.t
	pr := e.openPR("feature")
	e.enqueue(pr)
	y := e.commit(pr.HeadSHA, "newer", blob("feature.txt", "v2"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/feature", y))
	if q := e.entry(pr.Number); q.State != forge.QueueRemoved {
		t.Fatalf("entry after a push to the queued PR = %+v, want removed", q)
	}
}

func (e *env) groupState(sha string) forge.GroupState {
	e.t.Helper()
	for _, mg := range try(e.h.MergeGroups(e.ctx(), e.repo)).get(e.t) {
		if mg.CandidateSHA == sha {
			return mg.State
		}
	}
	e.t.Fatalf("no group with candidate %s", sha)
	return forge.GroupStateUnknown
}

func tree(files ...string) []gittree.Entry {
	out := make([]gittree.Entry, len(files))
	for i, f := range files {
		out[i] = blob(f, f)
	}
	return out
}

func testDequeue(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	a, b := e.openPR("a"), e.openPR("b")
	e.enqueue(a, b)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, [][]gittree.Entry{tree("a"), tree("a", "b")})).get(t)
	check(t, e.h.Dequeue(e.ctx(), e.repo, a.Number))
	if q := e.entry(a.Number); q.State != forge.QueueRemoved {
		t.Fatalf("dequeued entry = %+v", q)
	}
	if st := e.groupState(g.CandidateSHA); st == forge.GroupActive {
		t.Fatal("the group stayed active after a member was dequeued")
	}
	if q := e.entry(b.Number); q.State != forge.QueueQueued {
		t.Fatalf("surviving member = %+v, want queued again", q)
	}
	// A push to a grouped PR fails its group in the same way.
	c, d := e.openPR("c"), e.openPR("d")
	e.enqueue(c, d)
	g2 := try(qs.FormGroup(e.ctx(), e.repo, []int{c.Number, d.Number}, [][]gittree.Entry{tree("c"), tree("c", "d")})).get(t)
	check(t, qs.SetPullRequestHead(e.ctx(), e.repo, d.Number, e.commit(d.HeadSHA, "newer d", blob("d.txt", "2"))))
	if st := e.groupState(g2.CandidateSHA); st == forge.GroupActive {
		t.Fatal("the group stayed active after a member's head moved")
	}
	if q := e.entry(d.Number); q.State != forge.QueueRemoved {
		t.Fatalf("pushed entry = %+v", q)
	}
	if q := e.entry(c.Number); q.State != forge.QueueQueued {
		t.Fatalf("surviving member = %+v, want queued again", q)
	}
	// Removing an entry twice, or one that merged, is invalid.
	wantErr(t, e.h.Dequeue(e.ctx(), e.repo, a.Number), forge.ErrInvalid)
}

func testGroupCandidate(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	a, b := e.openPR("a"), e.openPR("b")
	e.enqueue(a, b)
	trees := [][]gittree.Entry{tree("a.txt"), tree("a.txt", "b.txt")}
	_, err := qs.FormGroup(e.ctx(), e.repo, nil, nil)
	wantErr(t, err, forge.ErrInvalid)
	_, err = qs.FormGroup(e.ctx(), e.repo, []int{a.Number, a.Number}, trees)
	wantErr(t, err, forge.ErrInvalid)
	_, err = qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, trees[:1])
	wantErr(t, err, forge.ErrInvalid)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, trees)).get(t)
	if g.BaseSHA != e.base || g.State != forge.GroupActive || len(g.Members) != 2 || g.CandidateSHA != g.Members[1].CandidateSHA {
		t.Fatalf("group = %+v", g)
	}
	// candidate_1 merges the base and a's head, candidate_2 merges candidate_1 and b's head.
	c1, c2 := g.Members[0].CandidateSHA, g.Members[1].CandidateSHA
	if got := try(e.h.Commits(e.ctx(), e.repo, g.BaseSHA, c2)).get(t); len(got) != 4 {
		t.Fatalf("Commits(base, candidate) = %d commits, want 4 (two heads, two merges)", len(got))
	} else {
		parents := map[string][]string{}
		for i := range got {
			parents[got[i].SHA] = got[i].Parents
		}
		if diff := cmp.Diff([]string{g.BaseSHA, a.HeadSHA}, parents[c1]); diff != "" {
			t.Fatalf("candidate 1 parents (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{c1, b.HeadSHA}, parents[c2]); diff != "" {
			t.Fatalf("candidate 2 parents (-want +got):\n%s", diff)
		}
	}
	if got := string(try(e.h.ReadFile(e.ctx(), e.repo, c1, "a.txt")).get(t)); got != "a.txt" {
		t.Fatalf("candidate 1 a.txt = %q", got)
	}
	if _, err := e.h.ReadFile(e.ctx(), e.repo, c1, "b.txt"); err == nil {
		t.Fatal("candidate 1 already has b.txt")
	}
	if files := try(e.h.Compare(e.ctx(), e.repo, g.BaseSHA, c2)).get(t); len(files) != 2 {
		t.Fatalf("Compare(base, candidate) = %+v", files)
	}
	if _, err := qs.FormGroup(e.ctx(), e.repo, []int{a.Number}, trees[:1]); !errors.Is(err, forge.ErrConflict) {
		t.Fatalf("grouping an already grouped PR: %v, want ErrConflict", err)
	}
}

func testEject(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	a, b, c := e.openPR("a"), e.openPR("b"), e.openPR("c")
	e.enqueue(a, b, c)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number, c.Number},
		[][]gittree.Entry{tree("a"), tree("a", "b"), tree("a", "b", "c")})).get(t)
	// Ejecting b keeps a's candidate and rebuilds c's on top of it.
	ng := try(qs.EjectMember(e.ctx(), e.repo, g.CandidateSHA, b.Number, [][]gittree.Entry{tree("a", "c")})).get(t)
	if ng.CandidateSHA == g.CandidateSHA || len(ng.Members) != 2 || ng.Members[0].PR != a.Number || ng.Members[1].PR != c.Number {
		t.Fatalf("new group = %+v (old %+v)", ng, g)
	}
	if ng.Members[0].CandidateSHA != g.Members[0].CandidateSHA || ng.Members[1].CandidateSHA == g.Members[2].CandidateSHA {
		t.Fatalf("members = %+v, want the prefix kept and the suffix rebuilt", ng.Members)
	}
	rebuilt := try(e.h.Commits(e.ctx(), e.repo, e.base, ng.CandidateSHA)).get(t)
	for i := range rebuilt {
		if c := &rebuilt[i]; c.SHA == ng.Members[1].CandidateSHA {
			if diff := cmp.Diff([]string{ng.Members[0].CandidateSHA, ng.Members[1].HeadSHA}, c.Parents); diff != "" {
				t.Fatalf("rebuilt candidate parents (-want +got):\n%s", diff)
			}
		}
	}
	if _, err := e.h.ReadFile(e.ctx(), e.repo, ng.CandidateSHA, "b"); err == nil {
		t.Fatal("the new candidate still has the ejected member's file")
	}
	if e.groupState(g.CandidateSHA) == forge.GroupActive || e.groupState(ng.CandidateSHA) != forge.GroupActive {
		t.Fatal("old group must fail and the new one be active")
	}
	if q := e.entry(b.Number); q.State != forge.QueueRemoved || q.HeadSHA != b.HeadSHA {
		t.Fatalf("ejected entry = %+v, want removed at head %s", q, b.HeadSHA)
	}
	if q := e.entry(a.Number); q.State != forge.QueueInGroup {
		t.Fatalf("remaining entry = %+v, want in group", q)
	}
	_, err := qs.EjectMember(e.ctx(), e.repo, g.CandidateSHA, a.Number, [][]gittree.Entry{tree("c")})
	wantErr(t, err, forge.ErrNotFound) // the old group is no longer active
	_, err = qs.EjectMember(e.ctx(), e.repo, ng.CandidateSHA, a.Number, nil)
	wantErr(t, err, forge.ErrInvalid) // one member to rebuild, no tree
	// Ejecting the last members fails the group and makes no new one.
	last := try(qs.EjectMember(e.ctx(), e.repo, ng.CandidateSHA, c.Number, nil)).get(t)
	if last.CandidateSHA == ng.CandidateSHA || len(last.Members) != 1 || last.Members[0].PR != a.Number {
		t.Fatalf("ejecting the last member = %+v, want a group of just a", last)
	}
	end := try(qs.EjectMember(e.ctx(), e.repo, last.CandidateSHA, a.Number, nil)).get(t)
	if end.CandidateSHA != "" || len(end.Members) != 0 {
		t.Fatalf("ejecting the only member made a group: %+v", end)
	}
	for _, mg := range try(e.h.MergeGroups(e.ctx(), e.repo)).get(t) {
		if mg.State == forge.GroupActive {
			t.Fatalf("active group %+v remains", mg)
		}
	}
}

func testRecordMerge(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	a, b := e.openPR("a"), e.openPR("b")
	e.enqueue(a, b)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, [][]gittree.Entry{tree("a"), tree("a", "b")})).get(t)
	merged := func(pr forge.PullRequest, commit string) forge.ObservedMerge {
		return forge.ObservedMerge{PR: pr.Number, HeadSHA: pr.HeadSHA, MergedCommit: commit, MergedBy: e.author}
	}
	// Validation: a stale head, an unknown commit and an unknown PR are refused, and nothing changes.
	stale := merged(a, g.Members[0].CandidateSHA)
	stale.HeadSHA = strings.Repeat("5", 40)
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, stale), forge.ErrConflict)
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, merged(a, strings.Repeat("6", 40))), forge.ErrNotFound)
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: 9999, MergedCommit: e.base}), forge.ErrNotFound)
	if got := try(e.resolve(e.main)).get(t); got != e.base || e.groupState(g.CandidateSHA) != forge.GroupActive {
		t.Fatal("a refused merge changed the base or the group")
	}
	// The first member merging moves the base and leaves the group unsettled until the last does.
	check(t, qs.RecordMerge(e.ctx(), e.repo, merged(a, g.Members[0].CandidateSHA)))
	if got := try(e.resolve(e.main)).get(t); got != g.Members[0].CandidateSHA {
		t.Fatalf("base = %s, want the merged commit", got)
	}
	if pr := try(e.h.GetPullRequest(e.ctx(), e.repo, a.Number)).get(t); pr.State != forge.PRMerged {
		t.Fatalf("PR = %+v", pr)
	}
	if st := e.groupState(g.CandidateSHA); st != forge.GroupFailed {
		t.Fatalf("group = %v after only one of two members merged, want failed", st)
	}
	if q := e.entry(b.Number); q.State != forge.QueueQueued {
		t.Fatalf("remaining member = %+v, want queued against the new base", q)
	}
	// Merging b through a's earlier candidate is refused: that candidate does not include b.
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, merged(b, g.Members[0].CandidateSHA)), forge.ErrInvalid)
	// A pull request that already merged cannot merge again.
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, merged(a, g.Members[0].CandidateSHA)), forge.ErrConflict)
}

func testRecordMergeSettlesGroup(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	a, b := e.openPR("a"), e.openPR("b")
	e.enqueue(a, b)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, [][]gittree.Entry{tree("a"), tree("a", "b")})).get(t)
	// Landing the group's last candidate merges every member.
	check(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: b.Number, HeadSHA: b.HeadSHA, MergedCommit: g.CandidateSHA, MergedBy: e.author}))
	if st := e.groupState(g.CandidateSHA); st != forge.GroupMerged {
		t.Fatalf("group = %v after every member merged, want merged", st)
	}
	for _, pr := range []*forge.PullRequest{&a, &b} {
		if got := try(e.h.GetPullRequest(e.ctx(), e.repo, pr.Number)).get(t); got.State != forge.PRMerged {
			t.Errorf("PR %d = %+v, want merged", pr.Number, got)
		}
		if q := e.entry(pr.Number); q.State != forge.QueueMerged {
			t.Errorf("entry = %+v, want merged", q)
		}
	}
	if n := len(try(e.h.ObservedMerges(e.ctx(), e.repo)).get(t)); n != 2 {
		t.Fatalf("ObservedMerges = %d, want one per member", n)
	}
}

func testBaseMoveFailsGroups(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	a := e.openPR("a")
	e.enqueue(a)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number}, [][]gittree.Entry{tree("a")})).get(t)
	moved := e.commit(e.base, "someone pushed to main", blob("m.txt", "m"))
	check(t, e.h.SetRef(e.ctx(), e.repo, e.main, moved))
	if st := e.groupState(g.CandidateSHA); st != forge.GroupFailed {
		t.Fatalf("group = %v after its base moved, want failed", st)
	}
	for _, mg := range try(e.h.MergeGroups(e.ctx(), e.repo)).get(t) {
		if mg.CandidateSHA == g.CandidateSHA && mg.BaseSHA != e.base {
			t.Fatalf("the failed group's BaseSHA was rewritten to %s: it must stay stale", mg.BaseSHA)
		}
	}
	if q := e.entry(a.Number); q.State != forge.QueueQueued {
		t.Fatalf("member = %+v, want queued again", q)
	}
}

func testRetarget(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/release", e.base))
	a := e.openPR("a")
	e.enqueue(a)
	check(t, qs.RetargetPullRequest(e.ctx(), e.repo, a.Number, "release"))
	if pr := try(e.h.GetPullRequest(e.ctx(), e.repo, a.Number)).get(t); pr.BaseRef != "release" {
		t.Fatalf("PR = %+v", pr)
	}
	if q := e.entry(a.Number); q.State != forge.QueueRemoved {
		t.Fatalf("retargeted entry = %+v, want removed", q)
	}
	wantErr(t, qs.RetargetPullRequest(e.ctx(), e.repo, a.Number, "no-such-branch"), forge.ErrNotFound)
}

func testQueueValidation(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	pr := e.openPR("feature")
	check(t, qs.SetPullRequestDraft(e.ctx(), e.repo, pr.Number, true))
	_, err := e.h.Enqueue(e.ctx(), e.repo, pr.Number, pr.HeadSHA)
	wantErr(t, err, forge.ErrConflict)
	check(t, qs.SetPullRequestDraft(e.ctx(), e.repo, pr.Number, false))
	e.enqueue(pr)
	check(t, qs.ClosePullRequest(e.ctx(), e.repo, pr.Number))
	if q := e.entry(pr.Number); q.State != forge.QueueRemoved {
		t.Fatalf("closing a queued PR left %+v", q)
	}
	_, err = e.h.Enqueue(e.ctx(), e.repo, pr.Number, pr.HeadSHA)
	wantErr(t, err, forge.ErrConflict)
	// Groups follow the pull requests' own base branch: members on different bases cannot share one.
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/release", e.base))
	a, b := e.openPR("a"), e.openPR("b")
	check(t, qs.RetargetPullRequest(e.ctx(), e.repo, b.Number, "release"))
	e.enqueue(a, b)
	_, err = qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, [][]gittree.Entry{tree("a"), tree("b")})
	wantErr(t, err, forge.ErrInvalid)
}

func testObservedMerges(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	pr := e.openPR("feature")
	e.enqueue(pr)
	merged := try(e.h.CommitTree(e.ctx(), e.repo, []string{e.base, pr.HeadSHA}, "merged", []gittree.Entry{blob("feature.txt", "feature")})).get(t)
	check(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: pr.Number, HeadSHA: pr.HeadSHA, MergedCommit: merged, MergedBy: e.author}))
	ms := try(e.h.ObservedMerges(e.ctx(), e.repo)).get(t)
	if len(ms) != 1 || ms[0].PR != pr.Number || ms[0].MergedCommit != merged || ms[0].MergedBy.ID != e.author.ID || ms[0].At.IsZero() {
		t.Fatalf("ObservedMerges = %+v", ms)
	}
	if q := e.entry(pr.Number); q.State != forge.QueueMerged {
		t.Fatalf("entry = %+v", q)
	}
}

func testPushPolicy(e *env) {
	t := e.t
	// The trusted base already holds the CI definitions; only changes to them are refused.
	ci := e.commit(e.base, "ci",
		blob(".github/workflows/ci.yml", "on: push"), blob(".github/actions/a/action.yml", "runs: x"),
		blob("CODEOWNERS", "* @alice"), blob("src/main.go", "package main"))
	p := e.pusherAt(e.coder, "pol", ci, forge.PushPolicy{Deny: denyProtected})
	refused := []forge.Change{
		change(".github/workflows/x.yml", "on: push"),
		change(".GitHub/Workflows/x.yml", "on: push"),
		change(".github./workflows /x.yml", "on: push"),
		change("GITHUB~1/WORKFL~1/x.yml", "on: push"),
		{Message: "delete workflow", Deletes: []string{".github/workflows/ci.yml"}},
		change(".github/actions/a/action.yml", "runs: evil"),
		change(".GITHUB/actions/a/action.yml", "runs: evil"),
		{Message: "delete action", Deletes: []string{".github/actions/a/action.yml"}},
		change("CODEOWNERS", "* @mallory"),
		change("CODEOWNERS.", "* @mallory"),
		{Message: "delete CODEOWNERS", Deletes: []string{"CODEOWNERS"}},
	}
	for i, c := range refused {
		if _, err := p.Push(e.ctx(), ci, c); !errors.Is(err, forge.ErrForbidden) {
			t.Errorf("refused change %d (%+v): error = %v, want ErrForbidden", i, c, err)
		}
	}
	if _, err := e.resolve("refs/heads/factory/pol"); !errors.Is(err, forge.ErrNotFound) {
		t.Fatalf("a refused push created the ref: %v", err)
	}
	// Ordinary files still work, and the workflows permission opens workflows but not the denied paths.
	next := try(p.Push(e.ctx(), ci, change("src/main.go", "package main // 2"))).get(t)
	wp := e.pusherAt(e.coder, "pol", ci, forge.PushPolicy{Workflows: true, Deny: denyProtected})
	next = try(wp.Push(e.ctx(), next, change(".github/workflows/x.yml", "on: push"))).get(t)
	_, err := wp.Push(e.ctx(), next, change("CODEOWNERS", "* @mallory"))
	wantErr(t, err, forge.ErrForbidden)
	_, err = wp.Push(e.ctx(), next, change(".github/actions/a/action.yml", "runs: evil"))
	wantErr(t, err, forge.ErrForbidden)
	// Without Workflows the same push is refused, now because the parent already carries the workflow.
	_, err = p.Push(e.ctx(), next, change("src/main.go", "package main // 3"))
	wantErr(t, err, forge.ErrForbidden)
}

// testPushTrustedBase checks that a push is judged by everything that differs from the trusted base, whatever the
// listed change touches, and that the parent must descend from that base.
func testPushTrustedBase(e *env) {
	t := e.t
	fork := try(e.h.ForkRepo(e.ctx(), e.repo, "fork")).get(t)
	for name, files := range map[string][]gittree.Entry{
		"workflow": {blob(".github/workflows/x.yml", "on: push")},
		"action":   {blob(".github/actions/a/action.yml", "runs: evil")},
		"owners":   {blob("CODEOWNERS", "* @mallory")},
	} {
		// An attacker's fork PR head carries the forbidden file, and the coder pushes an innocent change on top of it.
		head := try(e.h.CommitTree(e.ctx(), fork, []string{e.base}, "evil "+name, files)).get(t)
		check(t, e.h.SetRef(e.ctx(), fork, "refs/heads/evil-"+name, head))
		try(e.h.AddPullRequest(e.ctx(), e.repo, e.author, fork, "evil-"+name, e.main)).get(t)
		p := e.pusherWith(e.coder, "from-"+name, forge.PushPolicy{Deny: denyProtected})
		_, err := p.Push(e.ctx(), head, change("README", "hello"))
		if !errors.Is(err, forge.ErrForbidden) {
			t.Errorf("%s: push on top of a fork head error = %v, want ErrForbidden", name, err)
		}
		if _, rerr := e.resolve("refs/heads/factory/from-" + name); !errors.Is(rerr, forge.ErrNotFound) {
			t.Errorf("%s: a refused first push created the ref: %v", name, rerr)
		}
		// The same holds when the branch already exists, with the forbidden commit as its head.
		check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/factory/existing-"+name, head))
		q := e.pusherWith(e.coder, "existing-"+name, forge.PushPolicy{Deny: denyProtected})
		_, err = q.Push(e.ctx(), head, change("README", "hello"))
		wantErr(t, err, forge.ErrForbidden)
		if got := try(e.resolve("refs/heads/factory/existing-" + name)).get(t); got != head {
			t.Errorf("%s: the ref moved to %s", name, got)
		}
	}
	// An orphan commit does not descend from the trusted base.
	orphan := try(e.h.CommitTree(e.ctx(), e.repo, nil, "orphan", []gittree.Entry{blob("README", "orphan")})).get(t)
	p := e.pusher(e.coder, "orphaned")
	_, err := p.Push(e.ctx(), orphan, change("README", "hello"))
	wantErr(t, err, forge.ErrForbidden)
	if _, rerr := e.resolve("refs/heads/factory/orphaned"); !errors.Is(rerr, forge.ErrNotFound) {
		t.Fatalf("a push on an orphan created the ref: %v", rerr)
	}
	// A nil Deny fails closed at construction, and an unknown trusted base is invalid.
	check(t, e.h.AssignChange(e.ctx(), e.repo, "nodeny", e.coder, e.base))
	_, err = e.h.Pusher(e.ctx(), e.coder, e.repo, "refs/heads/factory/nodeny", forge.PushPolicy{})
	wantErr(t, err, forge.ErrInvalid)
	wantErr(t, e.h.AssignChange(e.ctx(), e.repo, "badbase", e.coder, strings.Repeat("4", 40)), forge.ErrInvalid)
}

func testRecordMergeConsistency(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	x, y := e.openPR("x"), e.openPR("y")
	// The base cannot move backwards: here main is ahead of the merged commit.
	ahead := try(e.h.CommitTree(e.ctx(), e.repo, []string{e.base, y.HeadSHA}, "main moved on", []gittree.Entry{blob("y.txt", "y")})).get(t)
	check(t, e.h.SetRef(e.ctx(), e.repo, e.main, ahead))
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: y.Number, HeadSHA: y.HeadSHA, MergedCommit: y.HeadSHA, MergedBy: e.author}), forge.ErrInvalid)
	if got := try(e.resolve(e.main)).get(t); got != ahead {
		t.Fatalf("main = %s after a refused merge, want %s", got, ahead)
	}
	// The merged commit must contain the pull request's head.
	unrelated := try(e.h.CommitTree(e.ctx(), e.repo, []string{ahead}, "does not contain x", []gittree.Entry{blob("z.txt", "z")})).get(t)
	wantErr(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: x.Number, HeadSHA: x.HeadSHA, MergedCommit: unrelated, MergedBy: e.author}), forge.ErrInvalid)
	if pr := try(e.h.GetPullRequest(e.ctx(), e.repo, x.Number)).get(t); pr.State != forge.PROpen {
		t.Fatalf("PR = %+v after a refused merge", pr)
	}
}

func testGroupLifecycle(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	// Two active groups on main: merging one fails the other.
	a, b, c, d := e.openPR("a"), e.openPR("b"), e.openPR("c"), e.openPR("d")
	e.enqueue(a, b, c, d)
	g1 := try(qs.FormGroup(e.ctx(), e.repo, []int{a.Number, b.Number}, [][]gittree.Entry{tree("a"), tree("a", "b")})).get(t)
	g2 := try(qs.FormGroup(e.ctx(), e.repo, []int{c.Number, d.Number}, [][]gittree.Entry{tree("c"), tree("c", "d")})).get(t)
	// Refs exist while the groups are active, and an unrelated branch move leaves them active.
	refA := "refs/heads/gh-readonly-queue/main/pr-" + strconv.Itoa(a.Number) + "-" + a.HeadSHA
	if got := try(e.resolve(refA)).get(t); got != g1.Members[0].CandidateSHA {
		t.Fatalf("queue ref = %s, want candidate %s", got, g1.Members[0].CandidateSHA)
	}
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/unrelated", e.commit(e.base, "unrelated", blob("u", "u"))))
	if e.groupState(g1.CandidateSHA) != forge.GroupActive || e.groupState(g2.CandidateSHA) != forge.GroupActive {
		t.Fatal("moving an unrelated branch failed an active group")
	}
	check(t, qs.RecordMerge(e.ctx(), e.repo, forge.ObservedMerge{PR: b.Number, HeadSHA: b.HeadSHA, MergedCommit: g1.CandidateSHA, MergedBy: e.author}))
	if e.groupState(g1.CandidateSHA) != forge.GroupMerged || e.groupState(g2.CandidateSHA) != forge.GroupFailed {
		t.Fatalf("groups = %v, %v; want the merged one merged and the other failed", e.groupState(g1.CandidateSHA), e.groupState(g2.CandidateSHA))
	}
	// A finished group, merged or failed, gives up its refs.
	if _, err := e.resolve(refA); !errors.Is(err, forge.ErrNotFound) {
		t.Fatalf("queue ref of a merged group survives: %v", err)
	}
	refC := "refs/heads/gh-readonly-queue/main/pr-" + strconv.Itoa(c.Number) + "-" + c.HeadSHA
	if _, err := e.resolve(refC); !errors.Is(err, forge.ErrNotFound) {
		t.Fatalf("queue ref of a failed group survives: %v", err)
	}
}

func testGroupOnOtherBase(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	rel := e.commit(e.base, "release", blob("rel.txt", "r"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/release", rel))
	head := e.commit(rel, "feature", blob("rel.txt", "r"), blob("f.txt", "f"))
	check(t, e.h.SetRef(e.ctx(), e.repo, "refs/heads/rel-feature", head))
	pr := try(e.h.AddPullRequest(e.ctx(), e.repo, e.author, e.repo, "rel-feature", "release")).get(t)
	e.enqueue(pr)
	g := try(qs.FormGroup(e.ctx(), e.repo, []int{pr.Number}, [][]gittree.Entry{tree("f.txt")})).get(t)
	if g.BaseSHA != rel {
		t.Fatalf("group base = %s, want the release head %s", g.BaseSHA, rel)
	}
	commits := try(e.h.Commits(e.ctx(), e.repo, rel, g.CandidateSHA)).get(t)
	for i := range commits {
		if commits[i].SHA == g.CandidateSHA {
			if diff := cmp.Diff([]string{rel, head}, commits[i].Parents); diff != "" {
				t.Fatalf("candidate parents (-want +got):\n%s", diff)
			}
			return
		}
	}
	t.Fatal("candidate not among its own commits")
}

func testCompareBestBaseSortsFirst(e *env) {
	t := e.t
	// Find a diamond whose dominated common ancestor D sorts before both children, so that choosing the first
	// common ancestor by SHA instead of the best one picks D.
	for range 200 {
		d := e.commit(e.base, "D")
		a := e.commit(d, "A", blob("a.txt", "a"))
		b := e.commit(d, "B", blob("b.txt", "b"))
		if d >= a || d >= b {
			continue
		}
		both := []gittree.Entry{blob("a.txt", "a"), blob("b.txt", "b")}
		m1 := try(e.h.CommitTree(e.ctx(), e.repo, []string{a, b}, "M1", both)).get(t)
		m2 := try(e.h.CommitTree(e.ctx(), e.repo, []string{b, a}, "M2", both)).get(t)
		// The merge bases of M1 and M2 are A and B, and D is dominated. Whichever sorts first is chosen, and diffing
		// it against the merge result adds exactly the other one's file.
		got := try(e.h.Compare(e.ctx(), e.repo, m1, m2)).get(t)
		want := "b.txt"
		if b < a {
			want = "a.txt"
		}
		if len(got) != 1 || got[0].Path != want || got[0].Status != forge.FileAdded {
			t.Fatalf("Compare(M1, M2) = %+v, want only %s added (merge base %s)", got, want, min(a, b))
		}
		return
	}
	t.Skip("no commit IDs with the needed order in 200 tries")
}

func testUndeclaredRenameIsRemovedPlusAdded(e *env) {
	t := e.t
	base := e.commit(e.base, "base", blob("old/name.txt", "identical"))
	head := e.commit(base, "head", blob("new/name.txt", "identical"))
	got := try(e.h.Compare(e.ctx(), e.repo, base, head)).get(t)
	status := map[string]forge.FileStatus{}
	for i := range got {
		status[got[i].Path] = got[i].Status
		if got[i].PreviousPath != "" {
			t.Errorf("%+v guessed a rename", got[i])
		}
	}
	want := map[string]forge.FileStatus{"old/name.txt": forge.FileRemoved, "new/name.txt": forge.FileAdded}
	if diff := cmp.Diff(want, status); diff != "" {
		t.Fatalf("Compare (-want +got):\n%s", diff)
	}
}

func testTransferChildClearsParent(e *env) {
	t := e.t
	parent, child := e.newIssue("parent", "p"), e.newIssue("child", "c")
	check(t, e.h.AddSubIssue(e.ctx(), e.repo, parent.Number, child.Number))
	other := try(e.h.AddRepo(e.ctx(), "other", true)).get(t)
	moved := try(e.h.TransferIssue(e.ctx(), e.repo, child.Number, other)).get(t)
	if moved.Parent != 0 {
		t.Fatalf("transferred child = %+v, want no parent", moved)
	}
	if got := try(e.h.GetIssue(e.ctx(), other, moved.Number)).get(t); got.Parent != 0 {
		t.Fatalf("re-read transferred child = %+v", got)
	}
	if subs := try(e.h.ListSubIssues(e.ctx(), e.repo, parent.Number)).get(t); len(subs) != 0 {
		t.Fatalf("old parent still lists %+v", subs)
	}
}

func testSupersessionIsPerProducer(e *env) {
	t := e.t
	check(t, e.job(leg("test", "1", "41", forge.ConclusionSuccess)))
	// A different app reusing the run ID and job name cannot supersede it, nor can another workflow file.
	check(t, e.job(func(j *forge.JobExecution) { j.ProducerAppID, j.RunAttempt, j.JobID = evilApp, "2", "42" }))
	check(t, e.job(func(j *forge.JobExecution) {
		j.WorkflowPath, j.RunAttempt, j.JobID = ".github/workflows/other.yml", "3", "43"
	}))
	if got := e.jobs()["41"]; got.SupersededBy != "" {
		t.Fatalf("job = %+v, want it not superseded by another producer or workflow", got)
	}
}

func testCheckRunConclusionNeedsCompletion(e *env) {
	t := e.t
	_, err := e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: e.base, Name: "x", Status: forge.CheckInProgress, Conclusion: forge.ConclusionSuccess})
	wantErr(t, err, forge.ErrInvalid)
	run := try(e.h.CreateCheckRun(e.ctx(), e.repo, forge.CheckRunInput{HeadSHA: e.base, Name: "x", Status: forge.CheckQueued})).get(t)
	_, err = e.h.UpdateCheckRun(e.ctx(), e.repo, run.ID, forge.CheckInProgress, forge.ConclusionFailure)
	wantErr(t, err, forge.ErrInvalid)
}

func testPullRequestStateChanges(e *env) {
	t := e.t
	qs := need[QueueSetup](e)
	pr := e.openPR("feature")
	e.enqueue(pr)
	check(t, qs.SetPullRequestDraft(e.ctx(), e.repo, pr.Number, true))
	if q := e.entry(pr.Number); q.State != forge.QueueRemoved {
		t.Fatalf("converting a queued PR to a draft left %+v", q)
	}
	check(t, qs.ClosePullRequest(e.ctx(), e.repo, pr.Number))
	wantErr(t, qs.ClosePullRequest(e.ctx(), e.repo, pr.Number), forge.ErrConflict)
	// A ref name must be a full one.
	wantErr(t, e.h.SetRef(e.ctx(), e.repo, "feature", e.base), forge.ErrInvalid)
}
