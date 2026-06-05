package maxcompute

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aliyun/aliyun-odps-go-sdk/odps"
	"github.com/goto/guardian/domain"
	"github.com/goto/guardian/pkg/log"
	"github.com/stretchr/testify/assert"
)

func TestODPSShouldRetry(t *testing.T) {
	type args struct {
		ctx context.Context
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "cancelled context error from inner function should not retried",
			args: args{
				ctx: context.TODO(),
				err: func() error {
					ctx, cancel := context.WithCancel(context.TODO())
					cancel()
					return ctx.Err()
				}(),
			},
			want: false,
		},
		{
			name: "dead context should not retried even when error is expected to be retried",
			args: args{
				ctx: func() context.Context {
					ctx, cancel := context.WithCancel(context.TODO())
					cancel()
					return ctx
				}(),
				err: errors.New("read: connection reset by peer"),
			},
			want: false,
		},
		{
			name: "retried",
			args: args{
				ctx: context.TODO(),
				err: errors.New("read: connection reset by peer"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := odpsShouldRetry(tt.args.ctx, tt.args.err); got != tt.want {
				t.Errorf("odpsShouldRetry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBatchLoadTablesSkippingFailuresSplitsOnlyFailedBatch(t *testing.T) {
	p := &provider{logger: log.NewNoop()}
	input := []string{"a", "b", "bad", "c", "d", "e", "f", "g"}
	var calls [][]string

	loadTables := func(tableNames []string) ([]*odps.Table, error) {
		calls = append(calls, append([]string(nil), tableNames...))
		for _, tableName := range tableNames {
			if tableName == "bad" {
				return nil, errors.New("bad table")
			}
		}

		loaded := make([]*odps.Table, 0, len(tableNames))
		for _, tableName := range tableNames {
			loaded = append(loaded, odps.NewTable(nil, "project", "schema", tableName))
		}
		return loaded, nil
	}

	loaded := p.batchLoadTablesSkippingFailures(context.Background(), loadTables, input, "project", "schema")

	wantLoadedNames := []string{"a", "b", "c", "d", "e", "f", "g"}
	if got := tableNamesFromODPSTables(loaded); !reflect.DeepEqual(got, wantLoadedNames) {
		t.Fatalf("loaded table names = %v, want %v", got, wantLoadedNames)
	}

	wantCalls := [][]string{
		{"a", "b", "bad", "c", "d", "e", "f", "g"},
		{"a", "b", "bad", "c"},
		{"a", "b"},
		{"bad", "c"},
		{"bad"},
		{"c"},
		{"d", "e", "f", "g"},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("load calls = %v, want %v", calls, wantCalls)
	}
}

func TestBatchLoadTablesSkippingFailuresSkipsMultipleFailedTables(t *testing.T) {
	p := &provider{logger: log.NewNoop()}
	input := []string{"1", "2", "bad1", "3", "bad2", "5", "6", "7", "bad3", "9"}
	failingTables := map[string]bool{
		"bad1": true,
		"bad2": true,
		"bad3": true,
	}

	loadTables := func(tableNames []string) ([]*odps.Table, error) {
		for _, tableName := range tableNames {
			if failingTables[tableName] {
				return nil, errors.New("bad table")
			}
		}

		loaded := make([]*odps.Table, 0, len(tableNames))
		for _, tableName := range tableNames {
			loaded = append(loaded, odps.NewTable(nil, "project", "schema", tableName))
		}
		return loaded, nil
	}

	loaded := p.batchLoadTablesSkippingFailures(context.Background(), loadTables, input, "project", "schema")

	wantLoadedNames := []string{"1", "2", "3", "5", "6", "7", "9"}
	if got := tableNamesFromODPSTables(loaded); !reflect.DeepEqual(got, wantLoadedNames) {
		t.Fatalf("loaded table names = %v, want %v", got, wantLoadedNames)
	}
}

func tableNamesFromODPSTables(tables []*odps.Table) []string {
	names := make([]string, 0, len(tables))
	for _, table := range tables {
		names = append(names, table.Name())
	}
	return names
}

func TestListAccess_PartialSuccess(t *testing.T) {
	t.Run("errors per resource are swallowed and partial results are returned", func(t *testing.T) {
		p := New("maxcompute", nil, &log.Noop{})

		pc := domain.ProviderConfig{
			Credentials: credentials{
				AccessKeyID:     "dummy",
				AccessKeySecret: "dummy",
				RegionID:        "dummy",
				ProjectName:     "dummy",
			},
		}
		resources := []*domain.Resource{
			{URN: "project-a", Type: "unsupported-type-1"},
			{URN: "project-b", Type: "unsupported-type-2"},
		}

		result, err := p.ListAccess(context.Background(), pc, resources)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})
}

func TestListAccessForUsers_PartialSuccess(t *testing.T) {
	t.Run("errors per resource are swallowed and partial results are returned", func(t *testing.T) {
		p := New("maxcompute", nil, &log.Noop{})

		pc := domain.ProviderConfig{
			Credentials: credentials{
				AccessKeyID:     "dummy",
				AccessKeySecret: "dummy",
				RegionID:        "dummy",
				ProjectName:     "dummy",
			},
		}
		resources := []*domain.Resource{
			{URN: "project-a", Type: "unsupported-type-1"},
			{URN: "project-b", Type: "unsupported-type-2"},
		}
		users := []string{"user1"}

		result, err := p.ListAccessForUsers(context.Background(), pc, resources, users)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})
}
