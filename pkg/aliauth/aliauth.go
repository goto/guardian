package aliauth

import (
	"fmt"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sts "github.com/alibabacloud-go/sts-20150401/v2/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/bearaujus/bptr"
	"github.com/google/uuid"
)

type aliAuth struct {
	accountId       string
	accessKeyId     string
	accessKeySecret string
	regionId        string
	ramRoleARN      string // optional (e,g. acs:ram::5123xxx:role/role-name)
}

func NewConfig(accessKeyId, accessKeySecret, regionID string, opts ...AliAuthOption) (*aliAuth, error) {
	if accessKeyId == "" {
		return nil, fmt.Errorf("access key id is empty")
	}
	if accessKeySecret == "" {
		return nil, fmt.Errorf("access key secret is empty")
	}
	if regionID == "" {
		return nil, fmt.Errorf("region id is empty")
	}
	a := &aliAuth{
		accessKeyId:     accessKeyId,
		accessKeySecret: accessKeySecret,
		regionId:        regionID,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.ApplyTo(a)
	}
	var err error
	a.accountId, err = a.validate()
	if err != nil {
		return nil, fmt.Errorf("fail to validate config: %w", err)
	}
	return a, nil
}

func (a *aliAuth) GetAccountId() string {
	return a.accountId
}

func (a *aliAuth) GetCredentials() (credentials.Credential, error) {
	cfg := &credentials.Config{
		Type:            bptr.FromStringNilAble("access_key"),
		AccessKeyId:     bptr.FromStringNilAble(a.accessKeyId),
		AccessKeySecret: bptr.FromStringNilAble(a.accessKeySecret),
	}
	if a.ramRoleARN != "" {
		cfg.Type = bptr.FromStringNilAble("ram_role_arn")
		cfg.RoleArn = bptr.FromStringNilAble(a.ramRoleARN)
		cfg.RoleSessionName = bptr.FromStringNilAble(fmt.Sprintf("aliauth_%s", uuid.New().String()))
	}
	creds, err := credentials.NewCredential(cfg)
	if err != nil {
		return nil, fmt.Errorf("fail to create a new credentials: %w", err)
	}
	return creds, nil
}

func (a *aliAuth) GetOpenAPIConfig() (*openapi.Config, error) {
	creds, err := a.GetCredentials()
	if err != nil {
		return nil, err
	}
	accessKeyId, err := creds.GetAccessKeyId()
	if err != nil {
		return nil, err
	}
	accessKeySecret, err := creds.GetAccessKeySecret()
	if err != nil {
		return nil, err
	}
	ret := &openapi.Config{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		RegionId:        bptr.FromStringNilAble(a.regionId),
		Credential:      creds,
	}
	if a.ramRoleARN != "" {
		securityToken, err := creds.GetSecurityToken()
		if err != nil {
			return nil, err
		}
		ret.SecurityToken = securityToken
	}
	return ret, nil
}

func (a *aliAuth) GetAccount() (account.Account, error) {
	creds, err := a.GetCredentials()
	if err != nil {
		return nil, err
	}
	return account.NewStsAccountWithCredential(creds), nil
}

func (a *aliAuth) validate() (string, error) {
	cfg, err := a.GetOpenAPIConfig()
	if err != nil {
		return "", err
	}
	cfg.Endpoint = bptr.FromStringNilAble(fmt.Sprintf("sts.%s.aliyuncs.com", a.regionId))
	client, err := sts.NewClient(cfg)
	if err != nil {
		return "", err
	}
	// [TESTED]
	// 1. We can call this function both when RAM role is present or not
	// 2. The error need to be masked, it exposes access key id
	ret, err := client.GetCallerIdentity()
	if err != nil {
		return "", fmt.Errorf("credentials config is not accepted by external service")
	}
	return bptr.ToStringSafe(ret.Body.AccountId), nil
}
