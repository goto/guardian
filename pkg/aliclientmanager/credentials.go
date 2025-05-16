package aliclientmanager

import (
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/aliyun/aliyun-odps-go-sdk/odps"
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
	ac, err := c.ToAliyunCredentials()
	if err != nil {
		return nil, err
	}
	cm, err := ac.GetCredential()
	if err != nil {
		return nil, err
	}
	// create a new object for AccessKeyId, AccessKeySecret, SecurityToken
	return &openapi.Config{
		AccessKeyId:     cm.AccessKeyId,
		AccessKeySecret: cm.AccessKeySecret,
		SecurityToken:   cm.SecurityToken,
		RegionId:        bptr.FromStringNilAble(c.RegionId),
		Credential:      ac,
	}, nil
}

func (c *Credentials) ToODPSAccount() (odpsAccount.Account, error) {
	ac, err := c.ToAliyunCredentials()
	if err != nil {
		return nil, err
	}
	cm, err := ac.GetCredential()
	if err != nil {
		return nil, err
	}
	var oc = &odps.Config{
		AccessId:  bptr.ToStringSafe(cm.AccessKeyId),
		AccessKey: bptr.ToStringSafe(cm.AccessKeySecret),
		StsToken:  bptr.ToStringSafe(cm.SecurityToken),
	}
	return oc.GenAccount(), nil
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
	if isSTSAccessKeyId(c.AccessKeyId) && c.SecurityToken == "" {
		return fmt.Errorf("security token is empty")
	}
	return nil
}

func isSTSAccessKeyId(accessKey string) bool {
	return strings.HasPrefix(strings.ToUpper(accessKey), "STS.")
}
