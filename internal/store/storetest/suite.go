// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package storetest is the conformance suite every [store.Store] must pass. Memstore runs it always and pgstore
// runs it when LIGHTSOUT_TEST_POSTGRES_URL is set. Each case names the requirement it covers.
package storetest

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store"
)

// Factory returns a new, empty store whose time comes from clock. The test closes it with t.Cleanup.
type Factory func(t *testing.T, clock func() time.Time) store.Store

// Clock is a hand-advanced clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock returns a clock at a fixed, arbitrary time.
func NewClock() *Clock { return &Clock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)} }

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t.In(time.FixedZone("test", 3600)) // not UTC: a store must normalize
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Rev is a valid revision digest for tests; n picks which.
func Rev(n byte) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 40)
	for i := range b {
		b[i] = hexd[(int(n)+i)%16]
	}
	return string(b)
}

// Record returns a valid audit record whose Target is target.
func Record(target string) audit.Record {
	return audit.Record{
		Actor:           audit.Actor{Kind: audit.ActorFactory, ID: "workload:test"},
		TemplateVersion: "test",
		Subject:         audit.Subject{Kind: audit.SubjectInstall, ID: "install-1"},
		Action:          audit.ActionAdmin,
		Target:          target,
		Outcome:         "ok",
	}
}

// BadRecord is rejected by the audit log, which is how the suite makes an append fail.
func BadRecord() audit.Record {
	r := Record("bad")
	r.Actor.ID = ""
	return r
}

// TestRepo is the repository ID the suite uses.
const TestRepo = "repo-1"

// NewRow returns a valid issue row.
func NewRow(id string) store.Row {
	return store.Row{Kind: store.KindIssue, ID: id, Repo: TestRepo, SchemaVersion: 1, Payload: json.RawMessage(`{"state":"new"}`)}
}

// Work returns a valid work item.
func Work(key string) store.WorkItem {
	return store.WorkItem{Key: key, Kind: "reread", Payload: json.RawMessage(`{"n":1}`)}
}

// Env is one case's store and helpers.
type Env struct {
	T     *testing.T
	Store store.Store
	Clock *Clock
}

// Denials returns a log over the denial chain.
func (e *Env) Denials() *audit.Log {
	e.T.Helper()
	l, err := audit.New(e.Store.Denials(), e.Clock.Now)
	if err != nil {
		e.T.Fatal(err)
	}
	return l
}

// DecisionLog returns a read-only log over the decision chain.
func (e *Env) DecisionLog() *audit.Log {
	e.T.Helper()
	l, err := audit.New(e.Store.Decisions(), e.Clock.Now)
	if err != nil {
		e.T.Fatal(err)
	}
	return l
}

// Tx runs fn in a transaction.
func (e *Env) Tx(fn func(tx store.Txn) error) error {
	e.T.Helper()
	return e.Store.Tx(e.T.Context(), func(_ context.Context, tx store.Txn) error { return fn(tx) })
}

// Run runs every conformance case against stores from f.
func Run(t *testing.T, f Factory) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*Env)
	}{
		{"CAS_VersionConflict_NFR5", casVersion},
		{"CAS_RevisionConflict_SEC10", casRevision},
		{"CAS_CreateTwiceConflicts_NFR5", casCreate},
		{"Rollback_FailedAppendUndoesStateAndConsume_SEC10", rollbackAppend},
		{"Replay_OneWinner_SEC10", replayOneWinner},
		{"Replay_ConsumedIsForever_SEC10", replayForever},
		{"Denials_SurviveRollback_NFR4", denialsSurviveRollback},
		{"Denials_WhileDecisionHeadHeld_NFR4", denialsWhileHeadHeld},
		{"Decisions_ReadOnlyView_NFR4", decisionsReadOnly},
		{"Deliveries_SameDigestIdempotent_NFR5", deliveriesIdempotent},
		{"Deliveries_DifferentDigestRejected_SEC1", deliveriesConflict},
		{"Deliveries_ReceiptAndEnqueueAtomic_NFR5", deliveriesAtomic},
		{"Leases_NoDoubleLease_NFR5", leasesExclusive},
		{"Leases_ExpiredIsReleasedWithNewGeneration_NFR5", leasesExpire},
		{"Leases_OldHolderCannotComplete_NFR5", leasesFenced},
		{"Leases_CompleteRollsBack_NFR5", leasesCompleteRollback},
		{"Chains_VerifyAndCheckpoint_NFR4", chainsVerify},
		{"Chains_RichRecordsRoundTrip_NFR4", chainsRich},
		{"Chains_TruncationFailsAgainstCheckpoint_NFR4", chainsTruncated},
		{"Inputs_Validated_SEC1", inputsValidated},
		{"Tx_UseAfterReturnFails_NFR5", txUseAfterReturn},
		{"Payloads_JSONBPoisonRejected_SEC1", payloadsRejected},
		{"Payloads_NumbersRoundTripExactly_NFR5", jsonPrecision},
		{"Payloads_EdgeOfValidIsAccepted_SEC1", payloadsAccepted},
		{"Keys_UntrustedKeysValidated_SEC1", keyValidation},
		{"Leases_CompleteWithGenerationZeroFails_NFR5", completeGenerationZero},
		{"Leases_OrderIsOldestFirst_NFR5", leaseOrder},
		{"Leases_TimesAreUTCMicroseconds_NFR5", leaseTime},
		{"Leases_ExpiredHolderIsFenced_NFR5", leaseExpiryFences},
		{"Leases_SubMicrosecondTTL_NFR5", leaseSubMicrosecondTTL},
		{"Leases_Reschedule_NFR5", leaseReschedule},
		{"Leases_DeadLetter_NFR5", leaseDeadLetter},
		{"Deliveries_CommitAfterErrorLeavesNoReceipt_NFR5", deliveryCommitAfterError},
		{"Audit_SealCalledOnceAndCheckedByBackend_NFR4", sealChecks},
		{"CAS_GrantBindsToCurrentRevision_CON8_SEC10", revisionBinding},
		{"CAS_TransferKeepsIDBumpsVersion_NFR5", transferPut},
		{"Chains_MissingCheckpointRefused_NFR4", chainsNeedCheckpoint},
		{"Checkpoint_RewriteBetweenReadsRefused_NFR4", checkpointRewriteRace},
		{"Authorize_EndToEndAndReplayDenial_SEC10", authorizeIntegration},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clock := NewClock()
			st := f(t, clock.Now)
			c.run(&Env{T: t, Store: st, Clock: clock})
		})
	}
}
