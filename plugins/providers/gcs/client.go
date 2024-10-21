package gcs

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/utils"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type gcsClient struct {
	client    *storage.Client
	projectID string
}

func newGCSClient(ctx context.Context, projectID string, credentialsJSON []byte) (*gcsClient, error) {
	creds, err := google.CredentialsFromJSON(ctx, credentialsJSON, "https://www.googleapis.com/auth/devstorage.full_control")
	if err != nil {
		return nil, fmt.Errorf("failed to obtain credentials: %w", err)
	}

	client := oauth2.NewClient(ctx, creds.TokenSource)
	client.Transport = otelhttp.NewTransport(client.Transport, otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
		return fmt.Sprintf("GCSClient %s", operation)
	}))

	clientService, err := storage.NewClient(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}
	return &gcsClient{
		client:    clientService,
		projectID: projectID,
	}, nil
}

// GetBuckets returns all buckets in the project
func (c *gcsClient) GetBuckets(ctx context.Context) ([]*Bucket, error) {
	var result []*Bucket
	it := c.client.Buckets(ctx, c.projectID)
	for {
		battrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		result = append(result, &Bucket{
			Name: battrs.Name,
		})
	}
	return result, nil
}

func (c *gcsClient) GrantBucketAccess(ctx context.Context, b Bucket, identity string, roleName iam.RoleName) error {
	bucketName := b.Name
	bucket := c.client.Bucket(bucketName)
	policy, err := bucket.IAM().Policy(ctx)
	if err != nil {
		return fmt.Errorf("Bucket(%q).IAM().Policy: %w", bucketName, err)
	}

	policy.Add(identity, roleName)
	if err := bucket.IAM().SetPolicy(ctx, policy); err != nil {
		return fmt.Errorf("Bucket(%q).IAM().SetPolicy: %w", bucketName, err)
	}

	return nil
}

func (c *gcsClient) RevokeBucketAccess(ctx context.Context, b Bucket, identity string, roleName iam.RoleName) error {
	bucketName := b.Name
	bucket := c.client.Bucket(bucketName)
	policy, err := bucket.IAM().Policy(ctx)
	if err != nil {
		return fmt.Errorf("Bucket(%q).IAM().Policy: %w", bucketName, err)
	}

	policy.Remove(identity, roleName)
	if err := bucket.IAM().SetPolicy(ctx, policy); err != nil {
		return fmt.Errorf("Bucket(%q).IAM().SetPolicy: %w", bucketName, err)
	}

	return nil
}

func (c *gcsClient) ListAccess(ctx context.Context, resources []*domain.Resource) (domain.MapResourceAccess, error) {
	result := make(domain.MapResourceAccess)
	eg, ctx := errgroup.WithContext(ctx)

	for _, resource := range resources {
		resource := resource
		eg.Go(func() error {
			var accessEntries []domain.AccessEntry

			bucket := c.client.Bucket(resource.URN)
			policy, err := bucket.IAM().Policy(ctx)
			if err != nil {
				return fmt.Errorf("Bucket(%q).IAM().Policy: %w", resource.URN, err)
			}

			for _, role := range policy.Roles() {
				for _, member := range policy.Members(role) {
					if strings.HasPrefix(member, "deleted:") {
						continue
					}
					accountType, accountID, err := parseMember(member)
					if err != nil {
						return err
					}

					// exclude unsupported account types
					if !utils.ContainsString(AllowedAccountTypes, accountType) {
						continue
					}

					accessEntries = append(accessEntries, domain.AccessEntry{
						Permission:  string(role),
						AccountID:   accountID,
						AccountType: accountType,
					})
				}
			}

			if accessEntries != nil {
				result[resource.URN] = accessEntries
			}

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return result, nil
}

func parseMember(member string) (accountType, accountID string, err error) {
	m := strings.Split(member, ":")
	if len(m) == 0 || len(m) > 2 {
		return "", "", fmt.Errorf("invalid bucket access member signature %q", member)
	}

	if len(m) == 2 {
		accountID = m[1]
	}
	accountType = m[0]

	return accountType, accountID, nil
}
