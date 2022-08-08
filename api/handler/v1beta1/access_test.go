package v1beta1_test

import (
	"context"
	"errors"
	"time"

	guardianv1beta1 "github.com/odpf/guardian/api/proto/odpf/guardian/v1beta1"
	"github.com/odpf/guardian/core/access"
	"github.com/odpf/guardian/domain"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *GrpcHandlersSuite) TestListAccesses() {
	s.Run("should return list of access on success", func() {
		s.setup()
		timeNow := time.Now()

		dummyAccesses := []domain.Access{
			{
				ID:             "test-id",
				Status:         "test-status",
				AccountID:      "test-account-id",
				AccountType:    "test-account-type",
				ResourceID:     "test-resource-id",
				Permissions:    []string{"test-permission"},
				ExpirationDate: &timeNow,
				AppealID:       "test-appeal-id",
				RevokedBy:      "test-revoked-by",
				RevokedAt:      &timeNow,
				RevokeReason:   "test-revoke-reason",
				CreatedAt:      timeNow,
				UpdatedAt:      timeNow,
				Resource: &domain.Resource{
					ID: "test-resource-id",
				},
				Appeal: &domain.Appeal{
					ID: "test-appeal-id",
				},
			},
		}
		expectedResponse := &guardianv1beta1.ListAccessesResponse{
			Accesses: []*guardianv1beta1.Access{
				{
					Id:             "test-id",
					Status:         "test-status",
					AccountId:      "test-account-id",
					AccountType:    "test-account-type",
					ResourceId:     "test-resource-id",
					Permissions:    []string{"test-permission"},
					ExpirationDate: timestamppb.New(timeNow),
					AppealId:       "test-appeal-id",
					RevokedBy:      "test-revoked-by",
					RevokedAt:      timestamppb.New(timeNow),
					RevokeReason:   "test-revoke-reason",
					CreatedAt:      timestamppb.New(timeNow),
					UpdatedAt:      timestamppb.New(timeNow),
					Resource: &guardianv1beta1.Resource{
						Id: "test-resource-id",
					},
					Appeal: &guardianv1beta1.Appeal{
						Id: "test-appeal-id",
					},
				},
			},
		}
		expectedFilter := domain.ListAccessesFilter{
			Statuses:     []string{"test-status"},
			AccountIDs:   []string{"test-account-id"},
			AccountTypes: []string{"test-account-type"},
			ResourceIDs:  []string{"test-resource-id"},
		}
		s.accessService.EXPECT().
			List(mock.AnythingOfType("*context.emptyCtx"), expectedFilter).
			Return(dummyAccesses, nil).Once()

		req := &guardianv1beta1.ListAccessesRequest{
			Statuses:     expectedFilter.Statuses,
			AccountIds:   expectedFilter.AccountIDs,
			AccountTypes: expectedFilter.AccountTypes,
			ResourceIds:  expectedFilter.ResourceIDs,
		}
		res, err := s.grpcServer.ListAccesses(context.Background(), req)

		s.NoError(err)
		s.Equal(expectedResponse, res)
		s.accessService.AssertExpectations(s.T())
	})

	s.Run("should return error if service returns an error", func() {
		s.setup()

		expectedError := errors.New("unexpected error")
		s.accessService.EXPECT().
			List(mock.AnythingOfType("*context.emptyCtx"), mock.AnythingOfType("domain.ListAccessesFilter")).
			Return(nil, expectedError).Once()

		req := &guardianv1beta1.ListAccessesRequest{}
		res, err := s.grpcServer.ListAccesses(context.Background(), req)

		s.Equal(codes.Internal, status.Code(err))
		s.Nil(res)
		s.accessService.AssertExpectations(s.T())
	})

	s.Run("should return error if there is an error when parsing the access", func() {
		s.setup()

		expectedAccesses := []domain.Access{
			{
				Resource: &domain.Resource{
					Details: map[string]interface{}{
						"foo": make(chan int), // invalid value
					},
				},
			},
		}
		s.accessService.EXPECT().
			List(mock.AnythingOfType("*context.emptyCtx"), mock.AnythingOfType("domain.ListAccessesFilter")).
			Return(expectedAccesses, nil).Once()

		req := &guardianv1beta1.ListAccessesRequest{}
		res, err := s.grpcServer.ListAccesses(context.Background(), req)

		s.Equal(codes.Internal, status.Code(err))
		s.Nil(res)
		s.accessService.AssertExpectations(s.T())
	})
}

func (s *GrpcHandlersSuite) TestGetAccess() {
	s.Run("should return access details on succes", func() {
		s.setup()
		timeNow := time.Now()

		accessID := "test-id"
		dummyAccess := &domain.Access{
			ID:             accessID,
			Status:         "test-status",
			AccountID:      "test-account-id",
			AccountType:    "test-account-type",
			ResourceID:     "test-resource-id",
			Permissions:    []string{"test-permission"},
			ExpirationDate: &timeNow,
			AppealID:       "test-appeal-id",
			RevokedBy:      "test-revoked-by",
			RevokedAt:      &timeNow,
			RevokeReason:   "test-revoke-reason",
			CreatedAt:      timeNow,
			UpdatedAt:      timeNow,
			Resource: &domain.Resource{
				ID: "test-resource-id",
			},
			Appeal: &domain.Appeal{
				ID: "test-appeal-id",
			},
		}
		expectedResponse := &guardianv1beta1.GetAccessResponse{
			Access: &guardianv1beta1.Access{
				Id:             accessID,
				Status:         "test-status",
				AccountId:      "test-account-id",
				AccountType:    "test-account-type",
				ResourceId:     "test-resource-id",
				Permissions:    []string{"test-permission"},
				ExpirationDate: timestamppb.New(timeNow),
				AppealId:       "test-appeal-id",
				RevokedBy:      "test-revoked-by",
				RevokedAt:      timestamppb.New(timeNow),
				RevokeReason:   "test-revoke-reason",
				CreatedAt:      timestamppb.New(timeNow),
				UpdatedAt:      timestamppb.New(timeNow),
				Resource: &guardianv1beta1.Resource{
					Id: "test-resource-id",
				},
				Appeal: &guardianv1beta1.Appeal{
					Id: "test-appeal-id",
				},
			},
		}
		s.accessService.EXPECT().
			GetByID(mock.AnythingOfType("*context.emptyCtx"), accessID).
			Return(dummyAccess, nil).Once()

		req := &guardianv1beta1.GetAccessRequest{Id: accessID}
		res, err := s.grpcServer.GetAccess(context.Background(), req)

		s.NoError(err)
		s.Equal(expectedResponse, res)
		s.accessService.AssertExpectations(s.T())
	})

	s.Run("should return error if access service returns an error", func() {
		testCases := []struct {
			name          string
			expectedError error
			expectedCode  codes.Code
		}{
			{
				"should return not found error if record not found",
				access.ErrAccessNotFound,
				codes.NotFound,
			},
			{
				"should return internal error if there's an unexpected error",
				errors.New("unexpected error"),
				codes.Internal,
			},
		}

		for _, tc := range testCases {
			s.Run(tc.name, func() {
				s.setup()

				s.accessService.EXPECT().
					GetByID(mock.AnythingOfType("*context.emptyCtx"), mock.AnythingOfType("string")).
					Return(nil, tc.expectedError).Once()

				req := &guardianv1beta1.GetAccessRequest{Id: "test-id"}
				res, err := s.grpcServer.GetAccess(context.Background(), req)

				s.Equal(tc.expectedCode, status.Code(err))
				s.Nil(res)
				s.accessService.AssertExpectations(s.T())
			})
		}
	})

	s.Run("should return error if there is an error when parsing the access", func() {
		s.setup()

		expectedAccess := &domain.Access{
			Resource: &domain.Resource{
				Details: map[string]interface{}{
					"foo": make(chan int), // invalid value
				},
			},
		}
		s.accessService.EXPECT().
			GetByID(mock.AnythingOfType("*context.emptyCtx"), mock.AnythingOfType("string")).
			Return(expectedAccess, nil).Once()

		req := &guardianv1beta1.GetAccessRequest{Id: "test-id"}
		res, err := s.grpcServer.GetAccess(context.Background(), req)

		s.Equal(codes.Internal, status.Code(err))
		s.Nil(res)
		s.accessService.AssertExpectations(s.T())
	})
}
