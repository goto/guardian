package server

import (
	"context"
	"net/http"

	ctx_logrus "github.com/grpc-ecosystem/go-grpc-middleware/tags/logrus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type authenticatedUserEmailContextKey struct{}

const (
	logrusActorKey = "actor"

	grpcgatewayHTTPPathKey = "http-path"
)

func headerAuthInterceptor(headerKey string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get(headerKey); len(v) > 0 {
				userEmail := v[0]
				ctx = context.WithValue(ctx, authenticatedUserEmailContextKey{}, userEmail)
			}
		}

		return handler(ctx, req)
	}
}

func enrichRequestMetadata(ctx context.Context, req *http.Request) metadata.MD {
	return metadata.New(map[string]string{
		grpcgatewayHTTPPathKey: req.URL.Path,
	})
}

func enrichLogrusFields() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		fields := make(logrus.Fields)

		if userEmail, ok := ctx.Value(authenticatedUserEmailContextKey{}).(string); ok {
			fields[logrusActorKey] = userEmail
		}

		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if len(md[grpcgatewayHTTPPathKey]) > 0 {
				fields["http_path"] = md[grpcgatewayHTTPPathKey][0]
			}
		}

		if len(fields) > 0 {
			ctx_logrus.AddFields(ctx, fields)
		}
		return handler(ctx, req)
	}
}
