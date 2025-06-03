package maxcompute

import (
	"context"
	"errors"
	"testing"
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
