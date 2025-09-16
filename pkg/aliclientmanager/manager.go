package aliclientmanager

import (
	"fmt"
	"strings"
	"sync"
	"time"

	sts "github.com/alibabacloud-go/sts-20150401/v2/client"
	"github.com/bearaujus/bptr"
)

const (
	// sessionInitDurationSeconds min 60 * 15 | max 60 * 60
	sessionInitDurationSeconds = 60 * 60
	// sessionDurationThresholdSeconds when Manager.credentials.RAMRoleARN != nil &&
	// time.Since(Manager.clientCreatedAt).Seconds() > percentage (%) from total sessionInitDurationSeconds.
	// it will renew the clientCredentials and creating a new client automatically (see Manager.isValid())
	sessionDurationThresholdSeconds = int(float64(sessionInitDurationSeconds) * 0.25)
)

type Manager[T any] struct {
	credentials        *Credentials
	validationRegionId string
	mu                 *sync.Mutex
	initialized        bool

	clientCreatedAt   time.Time
	clientCredentials *Credentials
	clientInitFunc    func(c Credentials) (T, error)
	client            T
}

func NewConfig[T any](credentials Credentials, clientInitFunc func(c Credentials) (T, error), opts ...Option[T]) (*Manager[T], error) {
	if err := credentials.validate(); err != nil {
		return nil, err
	}
	if clientInitFunc == nil {
		return nil, fmt.Errorf("client init function is nil")
	}
	man := &Manager[T]{
		credentials:    &credentials,
		mu:             &sync.Mutex{},
		clientInitFunc: clientInitFunc,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("received nil option")
		}
		opt(man)
	}
	if err := man.invoke(); err != nil {
		return nil, fmt.Errorf("fail to generate config: %w", err)
	}
	return man, nil
}

func GetCredentialsIdentity(credentials Credentials) (*sts.GetCallerIdentityResponseBody, error) {
	if err := credentials.validate(); err != nil {
		return nil, err
	}
	openAPIConfig, err := credentials.ToOpenAPIConfig()
	if err != nil {
		return nil, err
	}
	stsClient, err := sts.NewClient(openAPIConfig)
	if err != nil {
		return nil, err
	}
	// [TESTED]
	// 1. we can call this function both when ram role arn is present or not
	// 2. the error need to be masked, since it exposes access key id
	validationResp, err := stsClient.GetCallerIdentity()
	if err != nil {
		if strings.Contains(err.Error(), "InvalidSecurityToken.Expired") {
			return nil, fmt.Errorf("credentials config are not accepted by alicloud service: %w", err)
		}
		return nil, fmt.Errorf("credentials config are not accepted by alicloud service")
	}
	return validationResp.Body, nil
}

func (man *Manager[T]) GetClient() (T, error) {
	// [TESTED] need to lock here, otherwise when there are parallels execution when on the exact
	// time when sts token is expired, Manager.invoke() will be executed more than 1 time.
	// Also, this is the only one impl of Manager function that exposed to outside.
	man.mu.Lock()
	defer man.mu.Unlock()
	if !man.isValid() {
		if err := man.invoke(); err != nil {
			var nilT T
			return nilT, fmt.Errorf("fail to generate config: %w", err)
		}
	}
	return man.client, nil
}

func (man *Manager[T]) isValid() bool {
	if !man.initialized {
		return false
	}
	var (
		// check if source credentials are sts based (type: sts)
		// for now, we're returning the client instead of regenerating new one,
		// since it's not possible to regenerate the token if the token was sts based.
		typeSTS = isSTSAccessKeyId(man.credentials.AccessKeyId) && man.credentials.SecurityToken != ""
		// check if source credentials are access_key based (type: access_key)
		typeAccessKey = !typeSTS && man.credentials.RAMRoleARN == ""
		// check if source credentials are ram_role_arn based (type: ram_role_arn)
		typeRAMRoleARN = !(typeAccessKey || typeSTS) && man.credentials.RAMRoleARN != ""
	)
	if typeRAMRoleARN {
		var sessionDurationSeconds = int(time.Since(man.clientCreatedAt).Seconds())
		if sessionDurationSeconds >= sessionDurationThresholdSeconds {
			man.initialized = false
			return false
		}
	}
	return true
}

func (man *Manager[T]) invoke() error {
	openAPIConfig, err := man.credentials.ToOpenAPIConfig()
	if err != nil {
		return fmt.Errorf("fail to generate openapi config: %w", err)
	}
	// for client, we give STS credentials if ram role arn is present instead of giving the raw one
	validationRegionId := man.credentials.RegionId
	if man.validationRegionId != "" {
		validationRegionId = man.validationRegionId
	}
	var clientCredentials = Credentials{
		AccessKeyId:     bptr.ToStringSafe(openAPIConfig.AccessKeyId),
		AccessKeySecret: bptr.ToStringSafe(openAPIConfig.AccessKeySecret),
		SecurityToken:   bptr.ToStringSafe(openAPIConfig.SecurityToken),
		RegionId:        validationRegionId,
		RAMRoleARN:      man.credentials.RAMRoleARN,
	}
	credentialsIdentity, err := GetCredentialsIdentity(clientCredentials)
	if err != nil {
		return fmt.Errorf("fail to get credentials identity: %w", err)
	}
	// set account id
	clientCredentials.AccountId = bptr.ToStringSafe(credentialsIdentity.AccountId)
	// set original region id (if changed)
	clientCredentials.RegionId = man.credentials.RegionId
	man.clientCredentials = &clientCredentials
	// create a new credentials object to prevent values changes from outside
	var c = *man.clientCredentials
	man.client, err = man.clientInitFunc(c)
	if err != nil {
		return err
	}
	man.clientCreatedAt = time.Now()
	man.initialized = true
	return nil
}
