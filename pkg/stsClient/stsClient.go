package sts

import (
	"fmt"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	openapiV2 "github.com/alibabacloud-go/darabonba-openapi/v2/client"

	"github.com/alibabacloud-go/sts-20150401/client"
)

var assumeRoleDurationHours int64 = 1

type StsClient struct {
	client          *client.Client
	expiryTimeStamp time.Time
}

type Sts struct {
	clients map[string]*StsClient
}

func NewSTS() *Sts {
	return &Sts{
		clients: make(map[string]*StsClient),
	}
}

func (s *Sts) IsSTSTokenValid(clientIdentifier string) bool {
	client := s.clients[clientIdentifier]
	if client == nil {
		return false
	}

	return time.Now().Before(client.expiryTimeStamp)
}

func NewSTSClient(userAccessKeyID, userSecretAccessKey, regionID string) (*client.Client, error) {
	stsEndpoint := fmt.Sprintf("sts.%s.aliyuncs.com", regionID)

	config := &openapi.Config{
		AccessKeyId:     &userAccessKeyID,
		AccessKeySecret: &userSecretAccessKey,
		Endpoint:        &stsEndpoint,
	}

	stsClient, err := client.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize STS client: %w", err)
	}

	return stsClient, nil
}

func (s *Sts) GetSTSClient(clientIdentifier, userAccessKeyID, userSecret, regionID string) (*client.Client, error) {
	if c, ok := s.clients[clientIdentifier]; ok && s.IsSTSTokenValid(clientIdentifier) {
		return c.client, nil
	}

	stsClient, err := NewSTSClient(userAccessKeyID, userSecret, regionID)
	if err != nil {
		return nil, err
	}

	s.clients[clientIdentifier] = &StsClient{
		client:          stsClient,
		expiryTimeStamp: time.Now().Add(time.Duration(assumeRoleDurationHours) * time.Hour),
	}

	return stsClient, nil
}

func AssumeRole(stsClient *client.Client, roleArn, roleSessionName, regionID string) (*openapiV2.Config, error) {
	durationSeconds := assumeRoleDurationHours * int64(time.Hour.Seconds())
	request := client.AssumeRoleRequest{
		RoleArn:         &roleArn,
		RoleSessionName: &roleSessionName,
		DurationSeconds: &durationSeconds,
	}

	res, err := stsClient.AssumeRole(&request)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %w", err)
	}

	config := &openapiV2.Config{
		AccessKeyId:     res.Body.Credentials.AccessKeyId,
		AccessKeySecret: res.Body.Credentials.AccessKeySecret,
		SecurityToken:   res.Body.Credentials.SecurityToken,
		RegionId:        &regionID,
	}

	return config, nil
}
