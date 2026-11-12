package notifiers_test

import (
	"strings"
	"testing"

	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/plugins/notifiers"
)

func TestLarkV2AvailableInBothFactories(t *testing.T) {
	cfg := notifiers.Config{Provider: notifiers.ProviderTypeLarkV2, WorkerURL: "http://worker.example.com", WorkerToken: strings.Repeat("t", 32), Criteria: "false"}
	if _, err := notifiers.NewClient(&cfg, log.NewNoop()); err != nil {
		t.Fatal(err)
	}
	configs := []notifiers.Config{cfg}
	if _, err := notifiers.NewMultiClient(&configs, log.NewNoop()); err != nil {
		t.Fatal(err)
	}
	cfg.WorkerToken = ""
	if _, err := notifiers.NewClient(&cfg, log.NewNoop()); err == nil {
		t.Fatal("invalid v2 configuration accepted")
	}
}
