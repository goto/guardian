package aliauth

import (
	"fmt"
	"strings"
	"unicode"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/account"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/bearaujus/bptr"
	"github.com/google/uuid"
)

type AliAuth interface {
	GetCredentials() (credentials.Credential, error)
	GetOpenAPIConfig() (*openapi.Config, error)
	GetAccount() (account.Account, error)
}

type aliAuth struct {
	accessKeyId     string
	accessKeySecret string
	regionId        string
	ramRoleARN      string // optional (e,g. acs:ram::5123xxx:role/role-name)
}

func NewConfig(accessKeyId, accessKeySecret, regionID string, opts ...AliAuthOption) (AliAuth, error) {
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
	if a.ramRoleARN != "" {
		a.ramRoleARN = strings.TrimSpace(a.ramRoleARN) // acs:ram::5123xxx:role/role-name
		if a.ramRoleARN == "" {
			return nil, fmt.Errorf("ram role arn is invalid")
		}
		tmp := strings.ReplaceAll(strings.ToLower(a.ramRoleARN), strings.ToLower("acs:ram::"), "") // 5123xxx:role/role-name
		if tmp == strings.ToLower(a.ramRoleARN) {
			return nil, fmt.Errorf("ram role arn is invalid: '%s'", a.ramRoleARN)
		}
		tmpS := strings.Split(tmp, ":role/") // [0] 5123xxx, [1] role-name
		if len(tmpS) != 2 {
			return nil, fmt.Errorf("ram role arn is invalid: '%s'", a.ramRoleARN)
		}
		if tmpS[0] == "" { // 5123xxx
			return nil, fmt.Errorf("empty account id from ram role arn: '%s'", a.ramRoleARN)
		}
		if tmpS[1] == "" { // role-name
			return nil, fmt.Errorf("empty role name from ram role arn: '%s'", a.ramRoleARN)
		}
		for _, r := range tmpS[0] {
			if !unicode.IsDigit(r) {
				return nil, fmt.Errorf("invalid account id from ram role arn: '%s'", a.ramRoleARN)
			}
		}
		a.ramRoleARN = strings.ToLower(a.ramRoleARN)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return a, nil
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
		return nil, fmt.Errorf("failed to create a new credentials: %w", err)
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

func (a *aliAuth) validate() error {
	_, err := a.GetCredentials()
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}
	return nil
}
