// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"strconv"

	"github.com/elliott-davis/lightsout/internal/forge"
)

// AddCheckRun stores a check run exactly as given, from any producer, apart from assigning its ID.
func (f *Forge) AddCheckRun(ctx context.Context, cr forge.CheckRun) (forge.CheckRun, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.CheckRun{}, err
	}
	defer release()
	r, err := f.repo(cr.Repo)
	if err != nil {
		return forge.CheckRun{}, err
	}
	cr.ID = fmt.Sprintf("k%d", f.next())
	r.checks = append(r.checks, &cr)
	return cr, nil
}

// complete reports whether every provenance field of a job execution is set and well formed: full SHAs, a numeric
// attempt and an event.
func complete(j *forge.JobExecution) bool {
	attempt, err := strconv.Atoi(j.RunAttempt)
	return err == nil && attempt > 0 && j.Event != "" && fullSHA.MatchString(j.CandidateSHA) && fullSHA.MatchString(j.WorkflowCommit) &&
		j.ProducerAppID != "" && j.WorkflowRepo != "" && j.WorkflowPath != "" && j.JobKey != "" && j.RunID != "" && j.JobID != ""
}

// sameJob reports whether two executions are attempts of the same job: the same producer, workflow file, run and
// job. A different app cannot supersede an Actions job by reusing its run ID and name.
func sameJob(a, b *forge.JobExecution) bool {
	return a.ProducerAppID == b.ProducerAppID && a.WorkflowRepo == b.WorkflowRepo && a.WorkflowPath == b.WorkflowPath &&
		a.RunID == b.RunID && a.JobKey == b.JobKey
}

// successor names a later attempt for SupersededBy: its job ID, or a placeholder when it has none, so an older
// attempt never looks current.
func successor(j *forge.JobExecution, attempt int) string {
	if j.JobID != "" {
		return j.JobID
	}
	return "attempt:" + strconv.Itoa(attempt)
}

// AddJobExecution stores a job execution as given, with two rules the real forge also obeys. A record cannot claim
// complete provenance with a field missing or malformed (ErrInvalid), and the fake never completes an incomplete
// one. When two attempts of the same job (producer, workflow file, RunID and JobKey) exist, in either order of adding, the older one is marked
// superseded by the later one, so a stale success is always marked. JobKey is the rendered check name, matrix
// values included, so a re-run of one matrix leg supersedes only that leg.
func (f *Forge) AddJobExecution(ctx context.Context, je forge.JobExecution) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(je.Repo)
	if err != nil {
		return err
	}
	if je.Provenance == forge.ProvenanceComplete {
		if _, known := r.commits[je.CandidateSHA]; !known || !complete(&je) {
			return fmt.Errorf("job execution claims complete provenance with a missing or malformed field, or an unknown commit: %w", forge.ErrInvalid)
		}
	}
	attempt, aerr := strconv.Atoi(je.RunAttempt)
	if je.RunID != "" && je.JobKey != "" && aerr == nil {
		for _, old := range r.jobs {
			if !sameJob(old, &je) {
				continue
			}
			oldAttempt, oerr := strconv.Atoi(old.RunAttempt)
			switch {
			case oerr != nil:
			case oldAttempt < attempt && old.SupersededBy == "":
				old.SupersededBy = successor(&je, attempt)
			case oldAttempt > attempt && je.SupersededBy == "":
				je.SupersededBy = successor(old, oldAttempt)
			}
		}
	}
	r.jobs = append(r.jobs, &je)
	return nil
}

// ListCheckRuns implements [forge.CheckReader].
func (f *Forge) ListCheckRuns(ctx context.Context, repo forge.RepoID, sha string) ([]forge.CheckRun, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	var out []forge.CheckRun
	for _, c := range r.checks {
		if c.HeadSHA == sha {
			out = append(out, *c)
		}
	}
	return out, nil
}

// ListJobExecutions implements [forge.CheckReader]. Records come back as stored, plus supersession marks.
func (f *Forge) ListJobExecutions(ctx context.Context, repo forge.RepoID, sha string) ([]forge.JobExecution, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	err = f.incomplete("ListJobExecutions")
	if err != nil {
		return nil, err
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	var out []forge.JobExecution
	for _, j := range r.jobs {
		if j.CandidateSHA == sha {
			out = append(out, *j)
		}
	}
	return out, nil
}

// checkConclusion enforces that a conclusion exists exactly when the run is completed.
func checkConclusion(status forge.CheckStatus, conclusion forge.CheckConclusion) error {
	if (status == forge.CheckCompleted) != (conclusion != forge.ConclusionNone) {
		return fmt.Errorf("a check run has a conclusion exactly when it is completed (status %s, conclusion %s): %w", status, conclusion, forge.ErrInvalid)
	}
	return nil
}

// CreateCheckRun implements [forge.CheckWriter]. The producer is the factory's app ID. HeadSHA must be a full SHA
// of an existing commit (ErrNotFound), and a completed run needs a conclusion (ErrInvalid).
func (f *Forge) CreateCheckRun(ctx context.Context, repo forge.RepoID, in forge.CheckRunInput) (forge.CheckRun, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.CheckRun{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.CheckRun{}, err
	}
	if _, ok := r.commits[in.HeadSHA]; !ok || !fullSHA.MatchString(in.HeadSHA) {
		return forge.CheckRun{}, fmt.Errorf("check run head %q: %w", in.HeadSHA, forge.ErrNotFound)
	}
	err = checkConclusion(in.Status, in.Conclusion)
	if err != nil {
		return forge.CheckRun{}, err
	}
	cr := &forge.CheckRun{
		ID: fmt.Sprintf("k%d", f.next()), Repo: r.id, HeadSHA: in.HeadSHA, Name: in.Name,
		ProducerAppID: f.factoryApp, Status: in.Status, Conclusion: in.Conclusion, Started: f.clock(),
	}
	if in.Status == forge.CheckCompleted {
		cr.Completed = cr.Started
	}
	r.checks = append(r.checks, cr)
	return *cr, nil
}

// UpdateCheckRun implements [forge.CheckWriter]. A run another app produced is ErrForbidden, and a completed run
// needs a conclusion.
func (f *Forge) UpdateCheckRun(ctx context.Context, repo forge.RepoID, id string, status forge.CheckStatus, conclusion forge.CheckConclusion) (forge.CheckRun, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.CheckRun{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.CheckRun{}, err
	}
	for _, c := range r.checks {
		if c.ID != id {
			continue
		}
		if c.ProducerAppID != f.factoryApp {
			return forge.CheckRun{}, fmt.Errorf("check run %q was produced by app %q: %w", id, c.ProducerAppID, forge.ErrForbidden)
		}
		err = checkConclusion(status, conclusion)
		if err != nil {
			return forge.CheckRun{}, err
		}
		c.Status, c.Conclusion = status, conclusion
		if status == forge.CheckCompleted {
			c.Completed = f.clock()
		}
		return *c, nil
	}
	return forge.CheckRun{}, fmt.Errorf("check run %q: %w", id, forge.ErrNotFound)
}
