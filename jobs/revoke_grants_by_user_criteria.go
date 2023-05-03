package jobs

import (
	"context"
	"fmt"

	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/evaluator"
	"github.com/goto/guardian/plugins/identities"
)

type RevokeGrantsByUserCriteriaConfig struct {
	IAM                 domain.IAMConfig     `mapstructure:"iam"`
	UserCriteria        evaluator.Expression `mapstructure:"user_criteria"`
	ReassignOwnershipTo evaluator.Expression `mapstructure:"reassign_ownership_to"`
}

func (h *handler) RevokeGrantsByUserCriteria(ctx context.Context, c Config) error {
	h.logger.Info(fmt.Sprintf("starting %q job", RevokeGrantsByUserCriteria))

	var cfg RevokeGrantsByUserCriteriaConfig
	if err := c.Decode(&cfg); err != nil {
		return fmt.Errorf("invalid config for %s job: %w", RevokeGrantsByUserCriteria, err)
	}

	iamManager := identities.NewManager(h.crypto, h.validator)
	iamConfig, err := iamManager.ParseConfig(&cfg.IAM)
	if err != nil {
		return fmt.Errorf("parsing IAM config: %w", err)
	}
	iamClient, err := iamManager.GetClient(iamConfig)
	if err != nil {
		return fmt.Errorf("initializing IAM client: %w", err)
	}

	activeGrants, err := h.grantService.List(ctx, domain.ListGrantsFilter{
		Statuses: []string{string(domain.GrantStatusActive)},
	})
	if err != nil {
		return fmt.Errorf("listing active grants: %w", err)
	}

	grantsForUser := map[string][]*domain.Grant{}     // map[account_id][]grant
	grantsOwnedByUser := map[string][]*domain.Grant{} // map[owner][]grant
	uniqueUserEmails := map[string]bool{}             // map[account_id]bool
	for _, g := range activeGrants {
		if g.AccountType == domain.DefaultAppealAccountType {
			// collecting grants for individual users
			grantsForUser[g.AccountID] = append(grantsForUser[g.AccountID], &g)
			uniqueUserEmails[g.AccountID] = true
		} else if g.Owner != domain.SystemActorName {
			// collecting other grants owned by the user
			grantsOwnedByUser[g.Owner] = append(grantsOwnedByUser[g.AccountID], &g)
		}
	}

	for email := range uniqueUserEmails {
		user, err := iamClient.GetUser(email)
		if err != nil {
			h.logger.Error("getting user details from identity manager", "email", email, "error", err)
			continue
		}
		userDetails, ok := user.(map[string]interface{})
		if !ok {
			return fmt.Errorf("parsing user details: expected a map[string]interface{}, got %T instead; value is %q", user, user)
		}
		evaluationParams := map[string]interface{}{
			"user": userDetails,
		}

		// evaluating user criteria
		criteriaEvaluation, err := cfg.UserCriteria.EvaluateWithVars(evaluationParams)
		if err != nil {
			return fmt.Errorf("evaluating user_criteria: %w", err)
		}
		criteriaSatisfied, ok := criteriaEvaluation.(bool)
		if !ok {
			return fmt.Errorf("invalid type for user_criteria evaluation result: expected boolean, got %T; value is %q", criteriaEvaluation, criteriaEvaluation)
		} else if !criteriaSatisfied {
			continue
		}

		// revoking grants with account_id == email
		revokeGrantsFilter := domain.RevokeGrantsFilter{
			AccountIDs: []string{email},
		}
		h.logger.Info("revoking grants", "account_id", email)
		// revokedGrants, err := h.grantService.BulkRevoke(ctx, revokeGrantsFilter, domain.SystemActorName, "Revoked due to user deactivated")
		// if err != nil {
		// 	return fmt.Errorf("revoking grants: %w", err)
		// }
		revokedGrants := []*domain.Grant{}
		fmt.Printf("revokeGrantsFilter: %v\n", revokeGrantsFilter)
		revokedGrantIDs := []string{}
		for _, g := range revokedGrants {
			revokedGrantIDs = append(revokedGrantIDs, g.ID)
		}
		h.logger.Info("grant revocation successful", "count", len(revokedGrantIDs), "grant_ids", revokedGrantIDs)

		// reassigning grants owned by the user to the new owner
		for _, g := range grantsOwnedByUser[email] {
			newOwnerEvaluation, err := cfg.ReassignOwnershipTo.EvaluateWithVars(evaluationParams)
			if err != nil {
				return fmt.Errorf("evaluating reassign_ownership_to: %w", err)
			}
			newOwner, ok := newOwnerEvaluation.(string)
			if !ok {
				return fmt.Errorf("invalid type for reassign_ownership_to evaluation result: expected string, got %T instead; value is %q", newOwnerEvaluation, newOwnerEvaluation)
			} else if newOwner == "" {
				return fmt.Errorf("invalid value for reassign_ownership_to evaluation result: expected a non-empty string, got %q instead", newOwner)
			} else if err := h.validator.Var(newOwner, "email"); err != nil {
				return fmt.Errorf("invalid value for reassign_ownership_to evaluation result: expected a valid email address, got %q", newOwner)
			}

			h.logger.Info("updating grant owner", "grant_id", g.ID, "existing_owner", g.Owner, "new_owner", newOwner)
			g.Owner = newOwner
			fmt.Printf("newOwner: %v\n", newOwner)
			// if err := h.grantService.Update(ctx, g); err != nil { // TODO: refactor by creating grantServie.BulkUpdate
			// 	return fmt.Errorf("updating grant owner for %v: %w", g.ID, err)
			// }
			h.logger.Info("grant update successful", "grant_id", g.ID, "existing_owner", g.Owner, "new_owner", newOwner)
		}
	}

	return nil
}
