package server

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-playground/validator/v10"
	handlerv1beta1 "github.com/goto/guardian/api/handler/v1beta1"
	guardianv1beta1 "github.com/goto/guardian/api/proto/gotocompany/guardian/v1beta1"
	"github.com/goto/guardian/internal/store/postgres"
	"github.com/goto/guardian/jobs"
	"github.com/goto/guardian/pkg/auth"
	"github.com/goto/guardian/pkg/crypto"
	"github.com/goto/guardian/pkg/scheduler"
	"github.com/goto/guardian/pkg/tracing"
	"github.com/goto/guardian/plugins/notifiers"
	audit_repos "github.com/goto/salt/audit/repositories"
	"github.com/goto/salt/log"
	"github.com/goto/salt/mux"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/api/idtoken"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	ConfigFileName = "config"
)

const (
	GRPCMaxClientSendSize = 32 << 20
	defaultGracePeriod    = 5 * time.Second
)

// RunServer runs the application server
func RunServer(config *Config) error {
	logger := log.NewLogrus(log.LogrusWithLevel(config.LogLevel))
	crypto := crypto.NewAES(config.EncryptionSecretKeyKey)
	validator := validator.New()
	notifier, err := notifiers.NewClient(&config.Notifier)
	if err != nil {
		return err
	}

	shutdown, err := tracing.InitTracer(config.Telemetry)
	if err != nil {
		return err
	}
	defer shutdown()

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

	jobHandler := jobs.NewHandler(
		logger,
		services.GrantService,
		services.ProviderService,
		notifier,
		crypto,
		validator,
	)

	// init scheduler
	// TODO: allow timeout configuration for job handler context
	jobsMap := map[jobs.Type]func(context.Context, jobs.Config) error{
		jobs.TypeFetchResources:            jobHandler.FetchResources,
		jobs.TypeExpiringGrantNotification: jobHandler.GrantExpirationReminder,
		jobs.TypeRevokeExpiredGrants:       jobHandler.RevokeExpiredGrants,
	}

	enabledJobs := fetchJobsToRun(config)
	tasks := make([]*scheduler.Task, 0)
	for _, job := range enabledJobs {
		fn := jobsMap[job.Type]
		task := scheduler.Task{
			CronTab: job.Interval,
			Func:    func() error { return fn(context.Background(), job.Config) },
		}
		tasks = append(tasks, &task)
	}

	s, err := scheduler.New(tasks)
	if err != nil {
		return err
	}
	s.Run()

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
			grpc_recovery.UnaryServerInterceptor(
				grpc_recovery.WithRecoveryHandler(func(p interface{}) (err error) {
					logger.Error(string(debug.Stack()))
					return status.Errorf(codes.Internal, "Internal error, please check log")
				}),
			),
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
			authInterceptor,
			withLogrusContext(),
			otelgrpc.UnaryServerInterceptor(),
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
	))

	// init http proxy
	timeoutGrpcDialCtx, grpcDialCancel := context.WithTimeout(context.Background(), time.Second*5)
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
	)
	address := fmt.Sprintf(":%d", config.Port)
	grpcConn, err := grpc.DialContext(
		timeoutGrpcDialCtx,
		address,
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(GRPCMaxClientSendSize),
			grpc.MaxCallSendMsgSize(GRPCMaxClientSendSize),
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

	logger.Info(fmt.Sprintf("server running on %s", address))

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

func fetchJobsToRun(config *Config) []*jobs.Job {
	jobsToRun := make([]*jobs.Job, 0)

	if config.Jobs[jobs.TypeFetchResources].Enabled {
		job := config.Jobs[jobs.TypeFetchResources]
		job.Type = jobs.TypeFetchResources
		jobsToRun = append(jobsToRun, &job)
	}

	if config.Jobs[jobs.TypeExpiringAccessNotification].Enabled || config.Jobs[jobs.TypeExpiringGrantNotification].Enabled {
		job := config.Jobs[jobs.TypeExpiringAccessNotification]
		job.Type = jobs.TypeExpiringGrantNotification
		jobsToRun = append(jobsToRun, &job)
	}

	if config.Jobs[jobs.TypeRevokeExpiredAccess].Enabled || config.Jobs[jobs.TypeRevokeExpiredGrants].Enabled {
		job := config.Jobs[jobs.TypeRevokeExpiredAccess]
		job.Type = jobs.TypeRevokeExpiredGrants
		jobsToRun = append(jobsToRun, &job)
	}

	jobScheduleMapping := fetchDefaultJobScheduleMapping()
	for _, jobConfig := range jobsToRun {
		schedule, ok := jobScheduleMapping[jobConfig.Type]
		if ok && jobConfig.Interval == "" {
			jobConfig.Interval = schedule
		}
	}

	return jobsToRun
}

func fetchDefaultJobScheduleMapping() map[jobs.Type]string {
	return map[jobs.Type]string{
		jobs.TypeFetchResources:            "0 */2 * * *",
		jobs.TypeRevokeExpiredGrants:       "*/20 * * * *",
		jobs.TypeExpiringGrantNotification: "0 9 * * *",
	}
}

func getAuthInterceptor(config *Config) (grpc.UnaryServerInterceptor, error) {
	// default fallback to user email on header
	authInterceptor := withAuthenticatedUserEmail(config.Auth.Default.HeaderKey)

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
