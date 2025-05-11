package aliclientmanager

import (
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	odpsAccount "github.com/aliyun/aliyun-odps-go-sdk/odps/account"
	aliyun "github.com/aliyun/credentials-go/credentials"
	"github.com/bearaujus/bptr"
	"github.com/google/uuid"
)

type Credentials struct {
	AccountId       string
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	RegionId        string
	RAMRoleARN      string
}

func (c *Credentials) ToAliyunCredentials() (aliyun.Credential, error) {
	var aliyunCfg = &aliyun.Config{
		Type:            bptr.FromStringNilAble("access_key"),
		AccessKeyId:     bptr.FromStringNilAble(c.AccessKeyId),
		AccessKeySecret: bptr.FromStringNilAble(c.AccessKeySecret),
	}
	if c.SecurityToken != "" && isSTSAccessKeyId(c.AccessKeyId) {
		aliyunCfg.Type = bptr.FromStringNilAble("sts")
		aliyunCfg.SecurityToken = bptr.FromStringNilAble(c.SecurityToken)
	}
	// [TESTED] there are NO new sts token generation if the access key type is already sts
	if c.RAMRoleARN != "" && !isSTSAccessKeyId(c.AccessKeyId) {
		aliyunCfg.Type = bptr.FromStringNilAble("ram_role_arn")
		aliyunCfg.RoleArn = bptr.FromStringNilAble(c.RAMRoleARN)
		aliyunCfg.RoleSessionName = bptr.FromStringNilAble(fmt.Sprintf("aliclient-manager_%s", uuid.New().String()))
		aliyunCfg.RoleSessionExpiration = bptr.FromIntNilAble(sessionInitDurationSeconds)
		aliyunCfg.SecurityToken = nil
	}
	return aliyun.NewCredential(aliyunCfg)
}

func (c *Credentials) ToOpenAPIConfig() (*openapi.Config, error) {
	aliyunCreds, err := c.ToAliyunCredentials()
	if err != nil {
		return nil, err
	}
	cm, err := aliyunCreds.GetCredential()
	if err != nil {
		return nil, err
	}
	var securityToken = bptr.FromStringNilAble(c.SecurityToken)
	if c.RAMRoleARN != "" && isSTSAccessKeyId(bptr.ToStringSafe(cm.AccessKeyId)) {
		securityToken = bptr.FromStringNilAble(bptr.ToStringSafe(cm.SecurityToken)) // create a new object
	}
	return &openapi.Config{
		AccessKeyId:     bptr.FromStringNilAble(bptr.ToStringSafe(cm.AccessKeyId)),     // create a new object
		AccessKeySecret: bptr.FromStringNilAble(bptr.ToStringSafe(cm.AccessKeySecret)), // create a new object
		SecurityToken:   securityToken,
		RegionId:        bptr.FromStringNilAble(c.RegionId),
		Credential:      aliyunCreds,
	}, nil
}

func (c *Credentials) ToODPSAccount() (odpsAccount.Account, error) {
	aliyunCreds, err := c.ToAliyunCredentials()
	if err != nil {
		return nil, err
	}
	return odpsAccount.NewStsAccountWithCredential(aliyunCreds), nil
}

func (c *Credentials) validate() error {
	if c.AccessKeyId == "" {
		return fmt.Errorf("access key id is empty")
	}
	if c.AccessKeySecret == "" {
		return fmt.Errorf("access key secret is empty")
	}
	if c.RegionId == "" {
		return fmt.Errorf("region id is empty")
	}
	return nil
}

func isSTSAccessKeyId(accessKey string) bool {
	return strings.HasPrefix(strings.ToUpper(accessKey), "STS.")
}
