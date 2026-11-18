package maxcompute

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aliyun/aliyun-odps-go-sdk/odps/common"
	"github.com/aliyun/aliyun-odps-go-sdk/odps/restclient"
)

const securityCommandTimeout = 30 * time.Second

// An accepted or interrupted write may have completed remotely. Never replay it
// because a response or asynchronous polling request was lost.
type uncertainCommandError struct{ cause error }

func (e *uncertainCommandError) Error() string {
	return "MaxCompute command outcome unknown: " + e.cause.Error()
}
func (e *uncertainCommandError) Unwrap() error { return e.cause }

func waitAccessRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// runSecurityQuery uses request contexts for both submission and job polling.
// Unlike security.AuthQueryInstance.WaitForSuccess it also bounds async jobs.
func runSecurityQuery(ctx context.Context, client restclient.RestClient, project, query string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, securityCommandTimeout)
	defer cancel()
	readOnly := strings.HasPrefix(query, "SHOW ") || strings.HasPrefix(query, "LIST ") || strings.HasPrefix(query, "DESCRIBE ")
	var result string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		result, err = authorizationQuery(ctx, &client, project, query)
		if err == nil {
			return result, nil
		}
		var uncertain *uncertainCommandError
		// A known rejection (throttling/conflict) is safe to resubmit. An
		// uncertain write is reconciled by the caller's strict readback instead.
		if (!readOnly && errors.As(err, &uncertain)) || !odpsShouldRetry(ctx, err) || attempt == 2 {
			return "", err
		}
		if err = waitAccessRetry(ctx, time.Duration(1<<attempt)*100*time.Millisecond); err != nil {
			return "", err
		}
	}
	return result, err
}

func authorizationQuery(ctx context.Context, client *restclient.RestClient, project, query string) (string, error) {
	body, err := xml.Marshal(struct {
		XMLName              xml.Name `xml:"Authorization"`
		Query                string
		ResponseInJsonFormat bool
	}{Query: query, ResponseInJsonFormat: true})
	if err != nil {
		return "", err
	}
	rb := common.NewResourceBuilder(project)
	req, err := client.NewRequest(http.MethodPost, rb.Authorization(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set(common.HttpHeaderContentType, common.XMLContentType)
	var submitted struct{ Result string }
	var status int
	err = client.DoWithParseRes(req.WithContext(ctx), func(resp *http.Response) error {
		status = resp.StatusCode
		if status < 200 || status >= 300 {
			return restclient.NewHttpNotOk(resp)
		}
		return xml.NewDecoder(resp.Body).Decode(&submitted)
	})
	if err != nil {
		if status == 0 || status >= 500 || (status >= 200 && status < 300) {
			return "", &uncertainCommandError{err}
		}
		return "", err
	}
	if status == http.StatusOK {
		return submitted.Result, nil
	}
	if submitted.Result == "" {
		return "", &uncertainCommandError{errors.New("missing authorization job ID")}
	}
	for {
		if err := ctx.Err(); err != nil {
			return "", &uncertainCommandError{err}
		}
		req, err := client.NewRequest(http.MethodGet, rb.AuthorizationId(submitted.Result), nil)
		if err != nil {
			return "", &uncertainCommandError{err}
		}
		var state struct{ Result, Status string }
		err = client.DoWithParseFunc(req.WithContext(ctx), func(resp *http.Response) error {
			return xml.NewDecoder(resp.Body).Decode(&state)
		})
		if err != nil {
			return "", &uncertainCommandError{err}
		}
		switch state.Status {
		case "Terminated":
			return state.Result, nil
		case "Failed":
			return "", fmt.Errorf("MaxCompute authorization query failed: %s", state.Result)
		case "Running":
		default:
			return "", &uncertainCommandError{fmt.Errorf("unexpected authorization job status %q", state.Status)}
		}
		if err := waitAccessRetry(ctx, time.Second); err != nil {
			return "", &uncertainCommandError{err}
		}
	}
}
