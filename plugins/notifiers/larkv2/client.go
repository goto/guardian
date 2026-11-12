// Package larkv2 forwards structured notifications to the stateless Lark worker.
package larkv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goto/guardian/domain"
)

type Config struct {
	URL            string
	TimeoutSeconds int
}

type envelope struct {
	EventID   string                       `json:"event_id"`
	Recipient string                       `json:"recipient"`
	Type      string                       `json:"type"`
	Variables map[string]interface{}       `json:"variables"`
	Labels    map[string]string            `json:"labels,omitempty"`
	Approval  *domain.NotificationApproval `json:"approval,omitempty"`
}

type Notifier struct {
	endpoint string
	timeout  time.Duration
	http     *http.Client
	delays   []time.Duration
	store    CardStore
	reader   AppealReader
}

func New(config Config) (*Notifier, error) {
	u, err := url.Parse(config.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return nil, errors.New("lark_v2 worker_url must be an HTTP(S) origin without credentials or a path")
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 30
	}
	if config.TimeoutSeconds < 5 || config.TimeoutSeconds > 120 {
		return nil, errors.New("lark_v2 timeout_seconds must be between 5 and 120")
	}
	return &Notifier{endpoint: strings.TrimRight(config.URL, "/") + "/v1/notifications", timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		http: &http.Client{Timeout: 22 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, delays: []time.Duration{250 * time.Millisecond, time.Second}}, nil
}

func (n *Notifier) Notify(ctx context.Context, items []domain.Notification) []error {
	var errs []error
	for _, item := range groupApprovals(items) {
		if err := n.send(ctx, item); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (n *Notifier) send(parent context.Context, item domain.Notification) error {
	if item.Message.Type == domain.NotificationTypeApproverNotification && (item.Approval == nil || item.Approval.AppealID == "" || (item.Approval.ApprovalID == "" && len(item.Approval.Steps) == 0)) {
		return errors.New("lark_v2 approval notification is missing exact approval context")
	}
	payload := envelope{EventID: uuid.NewString(), Recipient: item.User, Type: item.Message.Type, Variables: presentationVariables(item.Message.Variables), Labels: item.Labels, Approval: item.Approval}
	data, err := json.Marshal(payload)
	if err != nil || len(data) > 64*1024 {
		return errors.New("lark_v2 notification cannot be encoded within the size limit")
	}
	ctx, cancel := context.WithTimeout(parent, n.timeout)
	defer cancel()
	tracked := n.store != nil && item.Message.Type == domain.NotificationTypeApproverNotification
	if tracked {
		if err := n.store.Prepare(ctx, cardForDelivery(payload.EventID, item, n.workerURL()), n.timeout+10*time.Second); err != nil {
			return errors.New("lark_v2 card receipt preparation failed")
		}
	}
	for attempt := 0; attempt <= len(n.delays); attempt++ {
		retry, retryAfter, err := n.attempt(ctx, data, payload.EventID, tracked)
		if err == nil {
			return nil
		}
		if !retry || attempt == len(n.delays) {
			return err
		}
		delay := n.delays[attempt]
		if retryAfter > delay {
			delay = retryAfter
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("lark_v2 delivery deadline exceeded; outcome may be unknown")
		case <-timer.C:
		}
	}
	return errors.New("lark_v2 delivery failed")
}

func (n *Notifier) attempt(ctx context.Context, data []byte, eventID string, tracked bool) (bool, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(data))
	if err != nil {
		return false, 0, errors.New("lark_v2 request could not be prepared")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		return true, 0, errors.New("lark_v2 delivery was not confirmed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var result struct {
			EventID   string `json:"event_id"`
			MessageID string `json:"message_id"`
			Bot       string `json:"bot"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&result) != nil || result.EventID != eventID || result.MessageID == "" || (result.Bot != "pending" && result.Bot != "notification") {
			return true, 0, errors.New("lark_v2 delivery response was not confirmed")
		}
		if tracked {
			if result.Bot != "pending" {
				return false, 0, errors.New("lark_v2 card receipt used an unexpected bot")
			}
			if err := n.store.Confirm(ctx, eventID, result.MessageID); err != nil {
				return true, 0, errors.New("lark_v2 card receipt confirmation failed")
			}
		}
		return false, 0, nil
	}
	retry := resp.StatusCode == 429 || resp.StatusCode >= 500
	delay := time.Duration(0)
	if seconds, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && seconds > 0 {
		if seconds > 5 {
			seconds = 5
		}
		delay = time.Duration(seconds) * time.Second
	}
	// Do not include a response body, URL, recipient or token in returned errors.
	return retry, delay, fmt.Errorf("lark_v2 delivery failed (status %d)", resp.StatusCode)
}
