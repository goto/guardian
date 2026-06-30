package domain_test

import (
	"testing"

	"github.com/goto/guardian/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Policy.HasStages
// ---------------------------------------------------------------------------

func TestPolicy_HasStages(t *testing.T) {
	tests := []struct {
		name   string
		policy domain.Policy
		want   bool
	}{
		{
			name:   "returns false when Stages is nil",
			policy: domain.Policy{},
			want:   false,
		},
		{
			name:   "returns false when Stages is empty slice",
			policy: domain.Policy{Stages: []string{}},
			want:   false,
		},
		{
			name:   "returns true when at least one stage is defined",
			policy: domain.Policy{Stages: []string{"review"}},
			want:   true,
		},
		{
			name:   "returns true when multiple stages are defined",
			policy: domain.Policy{Stages: []string{"legal", "security", "manager"}},
			want:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.HasStages())
		})
	}
}

// ---------------------------------------------------------------------------
// Policy.StageIndex
// ---------------------------------------------------------------------------

func TestPolicy_StageIndex(t *testing.T) {
	tests := []struct {
		name   string
		policy domain.Policy
		want   map[string]int
	}{
		{
			name:   "empty stages produces empty map",
			policy: domain.Policy{},
			want:   map[string]int{},
		},
		{
			name:   "single stage maps to index 0",
			policy: domain.Policy{Stages: []string{"review"}},
			want:   map[string]int{"review": 0},
		},
		{
			name:   "preserves order: first stage is 0, second is 1, etc.",
			policy: domain.Policy{Stages: []string{"legal", "security", "manager"}},
			want:   map[string]int{"legal": 0, "security": 1, "manager": 2},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.policy.StageIndex())
		})
	}
}

// ---------------------------------------------------------------------------
// Policy.ValidateStages
// ---------------------------------------------------------------------------

func TestPolicy_ValidateStages(t *testing.T) {
	manualStep := func(name, stage string) *domain.Step {
		return &domain.Step{
			Name:      name,
			Stage:     stage,
			Strategy:  domain.ApprovalStepStrategyManual,
			Approvers: []string{"approver@example.com"},
		}
	}

	tests := []struct {
		name      string
		policy    domain.Policy
		wantErrIs string // substring expected in error message; empty = no error
	}{
		{
			name: "no stages, no step stages — valid (backward-compatible)",
			policy: domain.Policy{
				Steps: []*domain.Step{
					manualStep("step1", ""),
					manualStep("step2", ""),
				},
			},
		},
		{
			name: "stages defined, all steps have valid stage references — valid",
			policy: domain.Policy{
				Stages: []string{"review", "approve"},
				Steps: []*domain.Step{
					manualStep("legal-review", "review"),
					manualStep("security-review", "review"),
					manualStep("manager-approve", "approve"),
				},
			},
		},
		{
			name: "no stages defined but a step references a stage — error",
			policy: domain.Policy{
				Steps: []*domain.Step{
					manualStep("step1", "review"),
				},
			},
			wantErrIs: "no stages defined",
		},
		{
			name: "stages defined but a step has no stage — error",
			policy: domain.Policy{
				Stages: []string{"review"},
				Steps: []*domain.Step{
					manualStep("step1", "review"),
					manualStep("step2", ""), // missing stage
				},
			},
			wantErrIs: "all steps must have a stage",
		},
		{
			name: "step references a stage name not in Stages list — error",
			policy: domain.Policy{
				Stages: []string{"review"},
				Steps: []*domain.Step{
					manualStep("step1", "nonexistent"),
				},
			},
			wantErrIs: "unknown stage",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.ValidateStages()
			if tc.wantErrIs == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrIs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Appeal.GetSortedStageIndices
// ---------------------------------------------------------------------------

func TestAppeal_GetSortedStageIndices(t *testing.T) {
	tests := []struct {
		name   string
		appeal domain.Appeal
		want   []int
	}{
		{
			name:   "no approvals returns empty slice",
			appeal: domain.Appeal{},
			want:   []int{},
		},
		{
			name: "single approval returns its index",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Index: 0, Status: domain.ApprovalStatusPending},
				},
			},
			want: []int{0},
		},
		{
			name: "stale approvals are excluded",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Index: 0, Status: domain.ApprovalStatusApproved, IsStale: true},
					{Index: 0, Status: domain.ApprovalStatusApproved},
					{Index: 1, Status: domain.ApprovalStatusPending},
				},
			},
			want: []int{0, 1},
		},
		{
			name: "multiple approvals sharing an index produce a single entry (parallel stage)",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Index: 0, Status: domain.ApprovalStatusPending},
					{Index: 0, Status: domain.ApprovalStatusPending},
					{Index: 1, Status: domain.ApprovalStatusBlocked},
				},
			},
			want: []int{0, 1},
		},
		{
			name: "indices are returned in ascending order regardless of insertion order",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Index: 2, Status: domain.ApprovalStatusPending},
					{Index: 0, Status: domain.ApprovalStatusApproved},
					{Index: 1, Status: domain.ApprovalStatusPending},
				},
			},
			want: []int{0, 1, 2},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.appeal.GetSortedStageIndices()
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Appeal.GetApprovalsByIndex
// ---------------------------------------------------------------------------

func TestAppeal_GetApprovalsByIndex(t *testing.T) {
	tests := []struct {
		name   string
		appeal domain.Appeal
		index  int
		want   []*domain.Approval
	}{
		{
			name:   "no approvals returns nil",
			appeal: domain.Appeal{},
			index:  0,
			want:   nil,
		},
		{
			name: "returns all non-stale approvals at the given index",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Name: "legal", Index: 0, Status: domain.ApprovalStatusPending},
					{Name: "security", Index: 0, Status: domain.ApprovalStatusPending},
					{Name: "manager", Index: 1, Status: domain.ApprovalStatusBlocked},
				},
			},
			index: 0,
			want: []*domain.Approval{
				{Name: "legal", Index: 0, Status: domain.ApprovalStatusPending},
				{Name: "security", Index: 0, Status: domain.ApprovalStatusPending},
			},
		},
		{
			name: "stale approvals at the index are excluded",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Name: "old-legal", Index: 0, Status: domain.ApprovalStatusApproved, IsStale: true},
					{Name: "legal", Index: 0, Status: domain.ApprovalStatusPending},
				},
			},
			index: 0,
			want: []*domain.Approval{
				{Name: "legal", Index: 0, Status: domain.ApprovalStatusPending},
			},
		},
		{
			name: "returns nil when no approval matches the index",
			appeal: domain.Appeal{
				Approvals: []*domain.Approval{
					{Name: "step1", Index: 0, Status: domain.ApprovalStatusApproved},
				},
			},
			index: 99,
			want:  nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.appeal.GetApprovalsByIndex(tc.index)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Appeal.ApplyPolicy — stage-based index assignment
// ---------------------------------------------------------------------------

func TestAppeal_ApplyPolicy_StageBasedIndexes(t *testing.T) {
	appeal := &domain.Appeal{
		ID:        "appeal-1",
		AccountID: "user@example.com",
		Role:      "viewer",
		Resource:  &domain.Resource{ID: "res-1"},
	}

	policy := &domain.Policy{
		ID:      "policy-1",
		Version: 1,
		Stages:  []string{"review", "approve"},
		Steps: []*domain.Step{
			{
				Name:      "legal-review",
				Stage:     "review",
				Strategy:  domain.ApprovalStepStrategyManual,
				Approvers: []string{"legal@example.com"},
			},
			{
				Name:      "security-review",
				Stage:     "review",
				Strategy:  domain.ApprovalStepStrategyManual,
				Approvers: []string{"security@example.com"},
			},
			{
				Name:      "manager-approve",
				Stage:     "approve",
				Strategy:  domain.ApprovalStepStrategyManual,
				Approvers: []string{"manager@example.com"},
			},
		},
	}

	err := appeal.ApplyPolicy(policy)
	require.NoError(t, err)
	require.Len(t, appeal.Approvals, 3)

	// Both "review" steps share index 0 — they execute in parallel.
	assert.Equal(t, 0, appeal.Approvals[0].Index, "legal-review should have index 0 (review stage)")
	assert.Equal(t, 0, appeal.Approvals[1].Index, "security-review should share index 0 (review stage)")
	// "approve" step gets index 1 — it executes after the review stage.
	assert.Equal(t, 1, appeal.Approvals[2].Index, "manager-approve should have index 1 (approve stage)")

	// Stage name is propagated to the approval.
	assert.Equal(t, "review", appeal.Approvals[0].Stage)
	assert.Equal(t, "review", appeal.Approvals[1].Stage)
	assert.Equal(t, "approve", appeal.Approvals[2].Stage)

	// First stage starts pending; second stage starts blocked.
	assert.Equal(t, domain.ApprovalStatusPending, appeal.Approvals[0].Status)
	assert.Equal(t, domain.ApprovalStatusPending, appeal.Approvals[1].Status)
	assert.Equal(t, domain.ApprovalStatusBlocked, appeal.Approvals[2].Status)
}

func TestAppeal_ApplyPolicy_NoStages_BackwardCompatible(t *testing.T) {
	appeal := &domain.Appeal{
		ID:        "appeal-1",
		AccountID: "user@example.com",
		Role:      "viewer",
		Resource:  &domain.Resource{ID: "res-1"},
	}

	policy := &domain.Policy{
		ID:      "policy-1",
		Version: 1,
		// No Stages: sequential behaviour by slice position.
		Steps: []*domain.Step{
			{
				Name:      "step1",
				Strategy:  domain.ApprovalStepStrategyManual,
				Approvers: []string{"approver1@example.com"},
			},
			{
				Name:      "step2",
				Strategy:  domain.ApprovalStepStrategyManual,
				Approvers: []string{"approver2@example.com"},
			},
		},
	}

	err := appeal.ApplyPolicy(policy)
	require.NoError(t, err)
	require.Len(t, appeal.Approvals, 2)

	assert.Equal(t, 0, appeal.Approvals[0].Index)
	assert.Equal(t, 1, appeal.Approvals[1].Index)
	assert.Equal(t, "", appeal.Approvals[0].Stage, "stage field is empty without stages")
	assert.Equal(t, "", appeal.Approvals[1].Stage)
}

func TestAppeal_ApplyPolicy_UnknownStage_ReturnsError(t *testing.T) {
	appeal := &domain.Appeal{
		ID:       "appeal-1",
		Resource: &domain.Resource{ID: "res-1"},
	}

	policy := &domain.Policy{
		ID:      "policy-1",
		Version: 1,
		Stages:  []string{"review"},
		Steps: []*domain.Step{
			{
				Name:      "step1",
				Stage:     "nonexistent", // not in Stages
				Strategy:  domain.ApprovalStepStrategyManual,
				Approvers: []string{"approver@example.com"},
			},
		},
	}

	err := appeal.ApplyPolicy(policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown stage")
}

// ---------------------------------------------------------------------------
// Appeal.AdvanceApproval — parallel stage behaviour
// ---------------------------------------------------------------------------

func TestAppeal_AdvanceApproval_ParallelStage_BothApproved(t *testing.T) {
	// When all approvals in a parallel stage are approved, the next stage unlocks.
	policy := &domain.Policy{
		ID:      "policy-1",
		Version: 1,
		Stages:  []string{"review", "approve"},
		Steps: []*domain.Step{
			{Name: "legal", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"legal@example.com"}},
			{Name: "security", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"security@example.com"}},
			{Name: "manager", Stage: "approve", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"manager@example.com"}},
		},
	}

	appeal := &domain.Appeal{
		Status: domain.AppealStatusPending,
		Approvals: []*domain.Approval{
			{Name: "legal", Index: 0, Status: domain.ApprovalStatusApproved},
			{Name: "security", Index: 0, Status: domain.ApprovalStatusApproved},
			{Name: "manager", Index: 1, Status: domain.ApprovalStatusBlocked},
		},
	}

	err := appeal.AdvanceApproval(policy)
	require.NoError(t, err)

	// Next stage unlocks.
	assert.Equal(t, domain.ApprovalStatusPending, appeal.Approvals[2].Status,
		"manager step should be unblocked once the review stage is fully approved")
	// Appeal is still pending (last stage not resolved yet).
	assert.Equal(t, domain.AppealStatusPending, appeal.Status)
}

func TestAppeal_AdvanceApproval_ParallelStage_OneStillPending(t *testing.T) {
	// When only one of two parallel approvals is approved, the next stage stays blocked.
	policy := &domain.Policy{
		ID:     "policy-1",
		Stages: []string{"review", "approve"},
		Steps: []*domain.Step{
			{Name: "legal", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"legal@example.com"}},
			{Name: "security", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"security@example.com"}},
			{Name: "manager", Stage: "approve", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"manager@example.com"}},
		},
	}

	appeal := &domain.Appeal{
		Status: domain.AppealStatusPending,
		Approvals: []*domain.Approval{
			{Name: "legal", Index: 0, Status: domain.ApprovalStatusApproved},
			{Name: "security", Index: 0, Status: domain.ApprovalStatusPending}, // still pending
			{Name: "manager", Index: 1, Status: domain.ApprovalStatusBlocked},
		},
	}

	err := appeal.AdvanceApproval(policy)
	require.NoError(t, err)

	assert.Equal(t, domain.ApprovalStatusBlocked, appeal.Approvals[2].Status,
		"next stage must stay blocked while any parallel approval is still pending")
	assert.Equal(t, domain.AppealStatusPending, appeal.Status)
}

func TestAppeal_AdvanceApproval_ParallelStage_OneRejected_SkipsRemaining(t *testing.T) {
	// When any parallel approval is rejected (without AllowFailed), the appeal is rejected
	// and remaining stages are skipped.
	policy := &domain.Policy{
		ID:     "policy-1",
		Stages: []string{"review", "approve"},
		Steps: []*domain.Step{
			{Name: "legal", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"legal@example.com"}},
			{Name: "security", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"security@example.com"}},
			{Name: "manager", Stage: "approve", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"manager@example.com"}},
		},
	}

	appeal := &domain.Appeal{
		Status: domain.AppealStatusPending,
		Approvals: []*domain.Approval{
			{Name: "legal", Index: 0, Status: domain.ApprovalStatusApproved},
			{Name: "security", Index: 0, Status: domain.ApprovalStatusRejected},
			{Name: "manager", Index: 1, Status: domain.ApprovalStatusBlocked},
		},
	}

	err := appeal.AdvanceApproval(policy)
	require.NoError(t, err)

	assert.Equal(t, domain.AppealStatusRejected, appeal.Status)
	// Remaining legal (already approved – no change needed).
	assert.Equal(t, domain.ApprovalStatusSkipped, appeal.Approvals[2].Status,
		"next-stage approvals must be skipped after a rejection")
}

func TestAppeal_AdvanceApproval_ParallelStage_AllApproved_LastStage_ApprovesAppeal(t *testing.T) {
	// When all approvals in the last parallel stage resolve, the appeal becomes approved.
	policy := &domain.Policy{
		ID:     "policy-1",
		Stages: []string{"review"},
		Steps: []*domain.Step{
			{Name: "legal", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"legal@example.com"}},
			{Name: "security", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"security@example.com"}},
		},
	}

	appeal := &domain.Appeal{
		Status: domain.AppealStatusPending,
		Approvals: []*domain.Approval{
			{Name: "legal", Index: 0, Status: domain.ApprovalStatusApproved},
			{Name: "security", Index: 0, Status: domain.ApprovalStatusApproved},
		},
	}

	err := appeal.AdvanceApproval(policy)
	require.NoError(t, err)

	assert.Equal(t, domain.AppealStatusApproved, appeal.Status,
		"appeal should be approved once the only (last) stage is fully resolved")
}

func TestAppeal_AdvanceApproval_ParallelStage_PendingApprovalRemainingStillPendingInStage(t *testing.T) {
	// A parallel-stage approval that is still pending keeps the whole stage unresolved,
	// so the appeal status stays pending and the next stage stays blocked.
	policy := &domain.Policy{
		ID:     "policy-1",
		Stages: []string{"review", "final"},
		Steps: []*domain.Step{
			{Name: "legal", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"legal@example.com"}},
			{Name: "security", Stage: "review", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"security@example.com"}},
			{Name: "final", Stage: "final", Strategy: domain.ApprovalStepStrategyManual, Approvers: []string{"manager@example.com"}},
		},
	}

	appeal := &domain.Appeal{
		Status: domain.AppealStatusPending,
		Approvals: []*domain.Approval{
			{Name: "legal", Index: 0, Status: domain.ApprovalStatusPending},
			{Name: "security", Index: 0, Status: domain.ApprovalStatusPending},
			{Name: "final", Index: 1, Status: domain.ApprovalStatusBlocked},
		},
	}

	err := appeal.AdvanceApproval(policy)
	require.NoError(t, err)

	assert.Equal(t, domain.AppealStatusPending, appeal.Status)
	assert.Equal(t, domain.ApprovalStatusBlocked, appeal.Approvals[2].Status)
}

// ---------------------------------------------------------------------------
// Step.ToApproval — Stage field propagation
// ---------------------------------------------------------------------------

func TestStep_ToApproval_PropagatesStageField(t *testing.T) {
	appeal := &domain.Appeal{
		ID:        "a1",
		AccountID: "user@example.com",
		Resource:  &domain.Resource{ID: "r1"},
	}
	policy := &domain.Policy{ID: "p1", Version: 1}

	step := domain.Step{
		Name:      "legal-review",
		Stage:     "review",
		Strategy:  domain.ApprovalStepStrategyManual,
		Approvers: []string{"legal@example.com"},
	}

	approval, err := step.ToApproval(appeal, policy, 0)
	require.NoError(t, err)

	assert.Equal(t, "review", approval.Stage, "Stage must be copied from Step to Approval")
	assert.Equal(t, "legal-review", approval.Name)
	assert.Equal(t, 0, approval.Index)
}

func TestStep_ToApproval_EmptyStageWhenNoStageSet(t *testing.T) {
	appeal := &domain.Appeal{
		ID:       "a1",
		Resource: &domain.Resource{ID: "r1"},
	}
	policy := &domain.Policy{ID: "p1", Version: 1}

	step := domain.Step{
		Name:      "step-1",
		Strategy:  domain.ApprovalStepStrategyManual,
		Approvers: []string{"approver@example.com"},
	}

	approval, err := step.ToApproval(appeal, policy, 0)
	require.NoError(t, err)

	assert.Equal(t, "", approval.Stage, "Stage must remain empty when not set on Step")
}

func TestStep_ToApproval_SecondIndexStartsBlocked(t *testing.T) {
	appeal := &domain.Appeal{ID: "a1", Resource: &domain.Resource{ID: "r1"}}
	policy := &domain.Policy{ID: "p1", Version: 1}
	step := domain.Step{
		Name:      "step-2",
		Stage:     "approve",
		Strategy:  domain.ApprovalStepStrategyManual,
		Approvers: []string{"approver@example.com"},
	}

	approval, err := step.ToApproval(appeal, policy, 1)
	require.NoError(t, err)

	assert.Equal(t, domain.ApprovalStatusBlocked, approval.Status,
		"approvals with index > 0 start as blocked regardless of stage")
}
