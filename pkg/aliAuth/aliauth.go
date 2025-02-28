package aliauth

import (
	"fmt"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	"github.com/alibabacloud-go/sts-20150401/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"

	openapiV2 "github.com/alibabacloud-go/darabonba-openapi/v2/client"
)

var assumeRoleDefaultDuration = time.Hour
var durationSeconds = int64(assumeRoleDefaultDuration.Seconds())

type aliAuthAccount struct {
	Account    account.Account
	ExpiryTime *time.Time // Only set for STS accounts
}

type AliAuthConfig struct {
	account  *aliAuthAccount
	regionID string
}

func NewConfig(ramUserAccessKeyID, ramUserAccessKeySecret, regionID, ramRole, roleSessionName string) (*AliAuthConfig, error) {
	if ramUserAccessKeyID == "" || ramUserAccessKeySecret == "" || regionID == "" {
		return nil, fmt.Errorf("access key ID, secret, and region ID are required")
	}

	if ramRole != "" && roleSessionName == "" {
		return nil, fmt.Errorf("role session name is required when assuming a role")
	}

	var authAccount *aliAuthAccount
	if ramRole == "" {
		authAccount = &aliAuthAccount{
			Account: account.NewAliyunAccount(ramUserAccessKeyID, ramUserAccessKeySecret),
		}
	} else {
		stsAcc, expiry, err := getSTSAccount(ramRole, roleSessionName, ramUserAccessKeyID, ramUserAccessKeySecret, regionID)
		if err != nil {
			return nil, err
		}
		authAccount = &aliAuthAccount{
			Account:    stsAcc,
			ExpiryTime: &expiry, // Ensure expiry time is always set
		}
	}

	return &AliAuthConfig{account: authAccount, regionID: regionID}, nil
}

func (a *AliAuthConfig) IsConfigValid() bool {
	switch a.account.Account.(type) {
	case *account.AliyunAccount:
		return true
	case *account.StsAccount:
		if a.account.ExpiryTime == nil {
			return false // Safety check to prevent nil dereference
		}
		return time.Now().Before(*a.account.ExpiryTime)
	default:
		return false
	}
}

func (a *AliAuthConfig) GetAccount() account.Account {
	return a.account.Account
}

func (a *AliAuthConfig) GetCredentials() (*openapiV2.Config, error) {
	var accessKeyId, accessKeySecret, securityToken string

	switch acc := a.account.Account.(type) {
	case *account.AliyunAccount:
		accessKeyId = acc.AccessId()
		accessKeySecret = acc.AccessKey()
	case *account.StsAccount:
		cred, err := acc.Credential()
		if err != nil {
			return &openapiV2.Config{}, fmt.Errorf("failed to get STS credentials: %w", err)
		}

		if cred.AccessKeyId == nil || cred.AccessKeySecret == nil || cred.SecurityToken == nil {
			return nil, fmt.Errorf("STS credentials contain nil values")
		}

		accessKeyId = *cred.AccessKeyId
		accessKeySecret = *cred.AccessKeySecret
		securityToken = *cred.SecurityToken
	default:
		return &openapiV2.Config{}, fmt.Errorf("unknown account type")
	}

	return &openapiV2.Config{
		AccessKeyId:     &accessKeyId,
		AccessKeySecret: &accessKeySecret,
		SecurityToken:   &securityToken,
		RegionId:        &a.regionID,
	}, nil
}

// getSTSAccount obtains an STS account by assuming a RAM role
func getSTSAccount(ramRole, roleSessionName, accessKeyID, accessKeySecret, regionID string) (*account.StsAccount, time.Time, error) {
	stsEndpoint := fmt.Sprintf("sts.%s.aliyuncs.com", regionID)

	config := &openapi.Config{
		AccessKeyId:     &accessKeyID,
		AccessKeySecret: &accessKeySecret,
		Endpoint:        &stsEndpoint,
	}

	stsClient, err := client.NewClient(config)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to initialize STS client: %w", err)
	}

	request := &client.AssumeRoleRequest{
		RoleArn:         &ramRole,
		RoleSessionName: &roleSessionName,
		DurationSeconds: &durationSeconds,
	}

	res, err := stsClient.AssumeRole(request)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to assume role: %w", err)
	}

	expiryTimeStamp := time.Now().Add(assumeRoleDefaultDuration)
	return account.NewStsAccount(*res.Body.Credentials.AccessKeyId, *res.Body.Credentials.AccessKeySecret, *res.Body.Credentials.SecurityToken), expiryTimeStamp, nil
}
