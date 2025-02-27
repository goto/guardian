package aliauth

import (
	"fmt"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	"github.com/alibabacloud-go/sts-20150401/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"
)

const assumeRoleDurationHours int64 = 1

var durationSeconds = assumeRoleDurationHours * int64(time.Hour.Seconds())

type AliAuthAccount struct {
	Account    account.Account
	ExpiryTime *time.Time // Only set for STS accounts
}

type AliAuthCredentials struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

type AliAuthConfig struct {
	account *AliAuthAccount
}

func NewConfig(ramUserAccessKeyID, ramUserAccessKeySecret, regionID, ramRole, roleSessionName string) (*AliAuthConfig, error) {
	if ramUserAccessKeyID == "" || ramUserAccessKeySecret == "" || regionID == "" {
		return nil, fmt.Errorf("access key ID, secret, and region ID are required")
	}

	if ramRole != "" && roleSessionName == "" {
		return nil, fmt.Errorf("role session name is required when assuming a role")
	}

	var authAccount *AliAuthAccount
	if ramRole == "" {
		authAccount = &AliAuthAccount{
			Account: account.NewAliyunAccount(ramUserAccessKeyID, ramUserAccessKeySecret),
		}
	} else {
		stsAcc, expiry, err := getSTSAccount(ramRole, roleSessionName, ramUserAccessKeyID, ramUserAccessKeySecret, regionID)
		if err != nil {
			return nil, err
		}
		authAccount = &AliAuthAccount{
			Account:    stsAcc,
			ExpiryTime: &expiry, // Ensure expiry time is always set
		}
	}

	return &AliAuthConfig{account: authAccount}, nil
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

func (a *AliAuthConfig) GetCredentials() (AliAuthCredentials, error) {
	switch acc := a.account.Account.(type) {
	case *account.AliyunAccount:
		return AliAuthCredentials{
			AccessKeyID:     acc.AccessId(),
			AccessKeySecret: acc.AccessKey(),
		}, nil
	case *account.StsAccount:
		cred, err := acc.Credential()
		if err != nil {
			return AliAuthCredentials{}, fmt.Errorf("failed to get STS credentials: %w", err)
		}
		return AliAuthCredentials{
			AccessKeyID:     *cred.AccessKeyId,
			AccessKeySecret: *cred.AccessKeySecret,
			SecurityToken:   *cred.SecurityToken,
		}, nil

	default:
		return AliAuthCredentials{}, fmt.Errorf("unknown account type")
	}
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

	expiryTimeStamp := time.Now().Add(time.Hour * time.Duration(assumeRoleDurationHours))
	return account.NewStsAccount(*res.Body.Credentials.AccessKeyId, *res.Body.Credentials.AccessKeySecret, *res.Body.Credentials.SecurityToken), expiryTimeStamp, nil
}
