package grant_test

import (
	"context"
	"testing"
	"time"

	"github.com/goto/guardian/core/grant"
	"github.com/goto/guardian/core/grant/mocks"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/mock"
)

func TestRevokeNotificationDrain(t *testing.T) {
	repo := new(mocks.Repository)
	provider := new(mocks.ProviderService)
	notifier := new(mocks.Notifier)
	audit := new(mocks.AuditLogger)
	g := &domain.Grant{ID: "grant", Resource: &domain.Resource{ID: "resource"}}
	repo.On("GetByID", mock.Anything, "grant").Return(g, nil)
	repo.On("Update", mock.Anything, mock.Anything).Return(nil)
	provider.On("RevokeAccess", mock.Anything, mock.Anything).Return(nil)
	audit.On("Log", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	notifier.On("Notify", mock.Anything, mock.Anything).Run(func(mock.Arguments) { close(started); <-release; close(finished) }).Return([]error(nil)).Once()
	s := grant.NewService(grant.ServiceDeps{Repository: repo, ProviderService: provider, Notifier: notifier, AuditLogger: audit, Logger: log.NewNoop()})
	if _, err := s.Revoke(context.Background(), "grant", "actor", "reason"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("notification never started")
	}
	drained := make(chan struct{})
	go func() {
		s.WaitNotifications()
		close(drained)
	}()
	select {
	case <-drained:
		t.Fatal("drain returned while notification was blocked")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("drain did not return after notification completed")
	}
	select {
	case <-finished:
	default:
		t.Fatal("drain returned before delivery finished")
	}
	notifier.AssertExpectations(t)
}
