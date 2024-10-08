package server

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/goto/guardian/domain"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"go.nhat.io/otelsql"

	"encoding/json"

	"github.com/go-playground/validator/v10"
	handlerv1beta1 "github.com/goto/guardian/api/handler/v1beta1"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/pkg/auth"
	"github.com/goto/guardian/pkg/crypto"
	"github.com/goto/guardian/pkg/log"
	"github.com/goto/guardian/pkg/opentelemetry"
	"github.com/goto/guardian/plugins/notifiers"
	audit_repos "github.com/goto/salt/audit/repositories"
	"github.com/goto/salt/mux"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"google.golang.org/api/idtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	ConfigFileName = "config"
)

const (
	// defaultGracePeriod is the default time to wait for graceful shutdown
	defaultGracePeriod = 5 * time.Second
)

// RunServer runs the application server
func RunServer(config *Config) error {
	logger := log.NewCtxLogger(config.LogLevel, []string{domain.TraceIDKey})
	crypto := crypto.NewAES(config.EncryptionSecretKeyKey)
	validator := validator.New()

	notifierConfig := []notifiers.Config{}
	if config.Notifiers != "" {
		var notifierMap map[string]interface{}
		err := json.Unmarshal([]byte(config.Notifiers), &notifierMap)
		if err != nil {
			return fmt.Errorf("failed to parse notifier config: %w", err)
		}
		var notifierConfigMap map[string]notifiers.Config
		err = mapstructure.Decode(notifierMap, &notifierConfigMap)
		if err != nil {
			return fmt.Errorf("failed to parse notifier config: %w", err)
		}

		for _, val := range notifierConfigMap {
			notifierConfig = append(notifierConfig, val)
		}
	} else {
		// map old to the new format
		oldConfig := config.Notifier
		oldConfig.Criteria = "true"
		notifierConfig = append(notifierConfig, oldConfig)
	}
	notifier, err := notifiers.NewMultiClient(&notifierConfig, logger)
	if err != nil {
		return err
	}

	ctx := context.Background()

	// var shutdownOtel = func() error { return nil }
	if config.Telemetry.Enabled {
		logger.Info(ctx, "open telemetry is initiating...")
		shutdownOtel, err := opentelemetry.Init(ctx, config.Telemetry)
		if err != nil {
			return fmt.Errorf("error initiating open telemetry: %w", err)
		}
		logger.Info(ctx, "open telemetry is initiated!")
		defer shutdownOtel()
	}

	services, err := InitServices(ServiceDeps{
		Config:    config,
		Logger:    logger,
		Validator: validator,
		Notifier:  notifier,
		Crypto:    crypto,
	})
	if err != nil {
		return fmt.Errorf("initializing services: %w", err)
	}

	// init grpc server
	logrusEntry := logrus.NewEntry(logrus.New()) // TODO: get logrus instance from `logger` var

	authInterceptor, err := getAuthInterceptor(config)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_logrus.StreamServerInterceptor(logrusEntry),
			otelgrpc.StreamServerInterceptor(),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
			authInterceptor,
			enrichLogrusFields(),
			otelgrpc.UnaryServerInterceptor(),
			grpc_recovery.UnaryServerInterceptor(
				grpc_recovery.WithRecoveryHandler(func(p interface{}) (err error) {
					logger.Error(context.Background(), string(debug.Stack()))
					return status.Errorf(codes.Internal, "Internal error, please check log")
				}),
			),
		)),
	)

	authUserContextKey := map[string]interface{}{
		"default": authenticatedUserEmailContextKey{},
		"oidc":    auth.OIDCEmailContextKey{},
	}

	protoAdapter := handlerv1beta1.NewAdapter()
	guardianv1beta1.RegisterGuardianServiceServer(grpcServer, handlerv1beta1.NewGRPCServer(
		services.ResourceService,
		services.ActivityService,
		services.ProviderService,
		services.PolicyService,
		services.AppealService,
		services.ApprovalService,
		services.GrantService,
		protoAdapter,
		authUserContextKey[config.Auth.Provider],
		logger,
	))

	// init http proxy
	timeoutInSeconds := time.Duration(config.GRPC.TimeoutInSeconds) * time.Second
	timeoutGrpcDialCtx, grpcDialCancel := context.WithTimeout(context.Background(), timeoutInSeconds)
	defer grpcDialCancel()

	headerMatcher := makeHeaderMatcher(config)
	gwmux := runtime.NewServeMux(
		runtime.WithErrorHandler(runtime.DefaultHTTPErrorHandler),
		runtime.WithIncomingHeaderMatcher(headerMatcher),
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames: true,
			},
			UnmarshalOptions: protojson.UnmarshalOptions{
				DiscardUnknown: true,
			},
		}),
		runtime.WithMetadata(enrichRequestMetadata),
	)

	// grpcPort has to be same as config.Port till the time guardian service can support both grpc and http in two different ports
	grpcPort := config.Port
	address := fmt.Sprintf(":%d", grpcPort)
	grpcConn, err := grpc.DialContext(
		timeoutGrpcDialCtx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(config.GRPC.MaxCallRecvMsgSize),
			grpc.MaxCallSendMsgSize(config.GRPC.MaxCallSendMsgSize),
		),
	)
	if err != nil {
		return err
	}

	runtimeCtx, runtimeCancel := context.WithCancel(context.Background())
	defer runtimeCancel()

	if err := guardianv1beta1.RegisterGuardianServiceHandler(runtimeCtx, gwmux, grpcConn); err != nil {
		return err
	}

	baseMux := http.NewServeMux()
	baseMux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	})
	baseMux.Handle("/api/", http.StripPrefix("/api", gwmux))

	logger.Info(runtimeCtx, fmt.Sprintf("server running on %s", address))

	return mux.Serve(runtimeCtx, address,
		mux.WithHTTP(baseMux),
		mux.WithGRPC(grpcServer),
		mux.WithGracePeriod(defaultGracePeriod),
	)
}

// Migrate runs the schema migration scripts
func Migrate(c *Config) error {
	store, err := getStore(c)
	if err != nil {
		return err
	}

	sqldb, _ := store.DB().DB()

	auditRepository := audit_repos.NewPostgresRepository(sqldb)
	if err := auditRepository.Init(context.Background()); err != nil {
		return fmt.Errorf("initializing audit repository: %w", err)
	}

	return store.Migrate()
}

func getStore(c *Config) (*postgres.Store, error) {
	store, err := postgres.NewStore(&c.DB)
	if c.Telemetry.Enabled {
		sqlDB, err := store.DB().DB()
		if err != nil {
			return nil, err
		}
		if err := otelsql.RecordStats(
			sqlDB,
			otelsql.WithSystem(semconv.DBSystemPostgreSQL),
			otelsql.WithInstanceName("default"),
		); err != nil {
			return nil, err
		}
		if err := store.DB().Use(otelgorm.NewPlugin()); err != nil {
			return store, err
		}
	}
	return store, err
}

func makeHeaderMatcher(c *Config) func(key string) (string, bool) {
	return func(key string) (string, bool) {
		switch strings.ToLower(key) {
		case
			strings.ToLower(c.Auth.Default.HeaderKey),
			strings.ToLower(c.AuditLogTraceIDHeaderKey):
			return key, true
		default:
			return runtime.DefaultHeaderMatcher(key)
		}
	}
}

func getAuthInterceptor(config *Config) (grpc.UnaryServerInterceptor, error) {
	// default fallback to user email on header
	authInterceptor := headerAuthInterceptor(config.Auth.Default.HeaderKey)

	if config.Auth.Provider == "oidc" {
		idtokenValidator, err := idtoken.NewValidator(context.Background())
		if err != nil {
			return nil, err
		}

		bearerTokenValidator := auth.NewOIDCValidator(idtokenValidator, config.Auth.OIDC)
		authInterceptor = bearerTokenValidator.WithOIDCValidator()
	}

	return authInterceptor, nil
}
