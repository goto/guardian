package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/goto/guardian/domain"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type notificationCardLookup interface {
	GetByMessageID(context.Context, string) (*domain.NotificationCard, error)
}

// Reuse the configured Guardian authentication interceptor, including OIDC when selected.
// A receipt is visible only to its recipient; callback payloads never authorize a wider scope.
type notificationAppealReader interface {
	GetByID(context.Context, string) (*domain.Appeal, error)
}

func registerNotificationCardLookup(mux *runtime.ServeMux, authenticate grpc.UnaryServerInterceptor, actorKey interface{}, store notificationCardLookup, readers ...notificationAppealReader) error {
	const method = "/guardian.NotificationCards/Get"
	return mux.HandlePath(http.MethodGet, "/v1beta1/notification-cards/{message_id}", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		ctx, err := runtime.AnnotateIncomingContext(r.Context(), mux, r, method)
		var result interface{}
		if err == nil {
			result, err = authenticate(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ interface{}) (interface{}, error) {
				actor, _ := ctx.Value(actorKey).(string)
				actor = strings.TrimSpace(actor)
				if actor == "" {
					return nil, status.Error(codes.Unauthenticated, "authenticated recipient is required")
				}
				messageID := params["message_id"]
				if messageID == "" || len(messageID) > 256 {
					return nil, status.Error(codes.InvalidArgument, "invalid message ID")
				}
				card, lookupErr := store.GetByMessageID(ctx, messageID)
				if errors.Is(lookupErr, gorm.ErrRecordNotFound) || (lookupErr == nil && (card == nil || !strings.EqualFold(strings.TrimSpace(card.Recipient), actor))) {
					return nil, status.Error(codes.NotFound, "card receipt not found")
				}
				if lookupErr != nil {
					return nil, status.Error(codes.Unavailable, "card receipt lookup failed")
				}
				result := map[string]interface{}{
					"message_id": card.MessageID, "appeal_id": card.AppealID, "revision": card.Revision,
					"recipient": card.Recipient, "approval_ids": card.ApprovalIDs, "closed": card.Closed, "created_at": card.CreatedAt,
				}
				if len(readers) > 0 {
					plan := []domain.NotificationApprovalStep{}
					if !card.Closed {
						appeal, readErr := readers[0].GetByID(ctx, card.AppealID)
						if readErr != nil {
							return nil, status.Error(codes.Unavailable, "approval plan unavailable")
						}
						if appeal != nil && uint32(appeal.Revision) == card.Revision {
							plan = domain.NotificationApprovalPlan(appeal, actor, card.ApprovalIDs)
						}
					}
					result["approval_plan"] = plan
				}
				return map[string]interface{}{"card": result}, nil
			})
		}
		if ctx == nil {
			ctx = r.Context()
		}
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			runtime.HTTPError(ctx, mux, &runtime.JSONPb{}, w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}
