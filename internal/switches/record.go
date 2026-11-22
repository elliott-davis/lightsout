// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// QualificationStatus is how far a switch's proposed setting has been tested.
type QualificationStatus string

// Qualification statuses.
const (
	// QualNone means no Acceptance run has passed.
	QualNone QualificationStatus = "none"
	// QualAcceptancePassed means Acceptance passed for the feature behind the switch.
	QualAcceptancePassed QualificationStatus = "acceptance-passed"
	// QualUnionQualified means Acceptance passed and the proposed setting was tested in a Union manifest that
	// qualified.
	QualUnionQualified QualificationStatus = "union-qualified"
	// QualUnionBlocked means Acceptance passed but the Union manifest that tested the proposed setting did not
	// qualify, so the feature is not ready to turn on.
	QualUnionBlocked QualificationStatus = "union-blocked"
)

// Qualification is a switch's qualification. The zero value means [QualNone]. The references are inputs from the callers that ran the tests.
type Qualification struct {
	Status        QualificationStatus
	AcceptanceRun string // reference of the passing Acceptance run
	ManifestID    string // ID of the Union manifest in which the proposed setting was tested
}

// Validate reports whether the qualification is complete: acceptance-passed needs a run reference, and both
// union states need an Acceptance run and a manifest ID. An unknown status is invalid.
func (q Qualification) Validate() error {
	switch q.Status {
	case QualNone, "": // the zero value is "none"
		return nil
	case QualAcceptancePassed:
		if q.AcceptanceRun == "" {
			return fmt.Errorf("qualification %s: acceptance run reference is required", q.Status)
		}
		return nil
	case QualUnionQualified, QualUnionBlocked:
		if q.AcceptanceRun == "" || q.ManifestID == "" {
			return fmt.Errorf("qualification %s: acceptance run reference and manifest ID are required", q.Status)
		}
		return nil
	}
	return fmt.Errorf("qualification status %s is unknown", escape(string(q.Status)))
}

// Record is what the factory remembers about one switch (FLG-3). Owner is an input: the feature's contract
// owner or ideator, resolved by the caller. This package never infers it.
type Record struct {
	Key               string
	Repo              string // "owner/name"
	Description       string
	Sources           []string // repository paths of the files that define the switch
	Owner             string
	FirstSeenRevision string
	FirstSeenAt       time.Time
	Default           Status // the default as last checked, normally [StatusDefaultOff]
	Qualification     Qualification
}

// NewRecord makes the record of sw first seen at revision rev and time at. Default comes from sw.Status(), so a
// switch that is not default-off cannot be recorded as off. Sources are the sorted, distinct paths of its
// definitions, and Description is the first non-empty one. Qualification is none until the caller sets it.
func NewRecord(repo string, sw Switch, rev string, at time.Time, owner string) Record {
	rec := Record{
		Key: sw.Key, Repo: repo, Owner: owner, FirstSeenRevision: rev, FirstSeenAt: at,
		Default: sw.Status(), Qualification: Qualification{Status: QualNone},
	}
	for i := range sw.Definitions {
		d := &sw.Definitions[i]
		rec.Sources = append(rec.Sources, d.Path)
		if rec.Description == "" {
			rec.Description = d.Description
		}
	}
	slices.Sort(rec.Sources)
	rec.Sources = slices.Compact(rec.Sources)
	return rec
}

// Render writes the records as the Markdown of a GitHub check (FLG-3): for each switch, whether it defaults off,
// whether Acceptance passed, the manifest that tested the proposed setting, the owner and the age. Rows are
// sorted by every field, so the output is deterministic. Every repository-supplied and caller-supplied string is
// escaped. Age is now minus FirstSeenAt, with now injected; it is "unknown" when FirstSeenAt is zero. A record
// with an invalid [Qualification] is an error and nothing is written.
func Render(w io.Writer, recs []Record, now time.Time) error {
	for i := range recs {
		if err := recs[i].Qualification.Validate(); err != nil {
			return fmt.Errorf("render record %s: %w", escape(recs[i].Key), err)
		}
	}
	var b strings.Builder
	b.WriteString("### Feature switches\n\n")
	if len(recs) == 0 {
		b.WriteString("No feature switches recorded.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	sorted := slices.Clone(recs)
	slices.SortStableFunc(sorted, func(x, y Record) int {
		return cmp.Or(
			cmp.Compare(x.Repo, y.Repo), cmp.Compare(x.Key, y.Key), cmp.Compare(x.FirstSeenRevision, y.FirstSeenRevision),
			x.FirstSeenAt.Compare(y.FirstSeenAt), cmp.Compare(x.Owner, y.Owner), cmp.Compare(x.Default, y.Default),
			cmp.Compare(x.Qualification.Status, y.Qualification.Status), cmp.Compare(x.Description, y.Description),
			cmp.Compare(strings.Join(x.Sources, "\x00"), strings.Join(y.Sources, "\x00")),
		)
	})
	b.WriteString("| Repo | Switch | Default | Acceptance | Manifest | Owner | Age | First seen | Sources | Description |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for i := range sorted {
		r := &sorted[i]
		srcs := slices.Clone(r.Sources)
		slices.Sort(srcs)
		for i, s := range srcs {
			srcs[i] = escape(s)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			cell(escape(r.Repo)),
			cell(escape(r.Key)),
			defaultText(r.Default),
			acceptanceText(r.Qualification),
			cell(manifestText(r.Qualification)),
			cell(escape(r.Owner)),
			ageText(r.FirstSeenAt, now),
			cell(escape(r.FirstSeenRevision)),
			cell(strings.Join(srcs, ", ")),
			cell(escape(r.Description)),
		)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func cell(escaped string) string {
	if escaped == "" {
		return "-"
	}
	return escaped
}

// defaultText is fixed text: the switch defaults off only when it was checked to be default-off.
func defaultText(s Status) string {
	switch s {
	case StatusDefaultOff:
		return "off"
	case StatusDefaultOn:
		return "ON"
	case StatusUnproven, StatusNotBoolean, StatusConflicting, StatusInvalid:
		return "not shown to be off (" + string(s) + ")"
	}
	return "unchecked"
}

func acceptanceText(q Qualification) string {
	switch q.Status {
	case QualAcceptancePassed:
		return "passed (" + escape(q.AcceptanceRun) + ")"
	case QualUnionQualified:
		return "passed (" + escape(q.AcceptanceRun) + "), union qualified"
	case QualUnionBlocked:
		return "passed (" + escape(q.AcceptanceRun) + "), union blocked"
	case QualNone:
	}
	return "not passed"
}

// manifestText is the Union manifest ID, shown only for the union states.
func manifestText(q Qualification) string {
	if q.Status == QualUnionQualified || q.Status == QualUnionBlocked {
		return escape(q.ManifestID)
	}
	return ""
}

func ageText(first, now time.Time) string {
	if first.IsZero() {
		return "unknown"
	}
	d := now.Sub(first)
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
}
