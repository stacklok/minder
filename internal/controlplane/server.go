//
// Copyright 2023 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	gh "github.com/google/go-github/v61/github"
	"github.com/gorilla/handlers"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/open-feature/go-sdk/openfeature"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	_ "github.com/signalfx/splunk-otel-go/instrumentation/github.com/lib/pq/splunkpq" // Auto-instrumented version of lib/pq
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	"github.com/stacklok/minder/internal/assets"
	"github.com/stacklok/minder/internal/auth"
	"github.com/stacklok/minder/internal/authz"
	"github.com/stacklok/minder/internal/authz/mock"
	serverconfig "github.com/stacklok/minder/internal/config/server"
	"github.com/stacklok/minder/internal/controlplane/metrics"
	"github.com/stacklok/minder/internal/crypto"
	"github.com/stacklok/minder/internal/db"
	"github.com/stacklok/minder/internal/events"
	"github.com/stacklok/minder/internal/logger"
	"github.com/stacklok/minder/internal/marketplaces"
	"github.com/stacklok/minder/internal/profiles"
	"github.com/stacklok/minder/internal/projects"
	"github.com/stacklok/minder/internal/providers"
	ghprov "github.com/stacklok/minder/internal/providers/github"
	"github.com/stacklok/minder/internal/providers/github/clients"
	ghmanager "github.com/stacklok/minder/internal/providers/github/manager"
	"github.com/stacklok/minder/internal/providers/github/service"
	"github.com/stacklok/minder/internal/providers/manager"
	"github.com/stacklok/minder/internal/providers/ratecache"
	provtelemetry "github.com/stacklok/minder/internal/providers/telemetry"
	"github.com/stacklok/minder/internal/repositories/github"
	"github.com/stacklok/minder/internal/repositories/github/webhooks"
	"github.com/stacklok/minder/internal/ruletypes"
	"github.com/stacklok/minder/internal/util"
	pb "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

const metricsPath = "/metrics"

var (
	readHeaderTimeout = 2 * time.Second
)

// Server represents the controlplane server
type Server struct {
	store               db.Store
	cfg                 *serverconfig.Config
	evt                 events.Publisher
	mt                  metrics.Metrics
	provMt              provtelemetry.ProviderMetrics
	grpcServer          *grpc.Server
	vldtr               auth.JwtValidator
	providerAuthFactory func(string, bool) (*oauth2.Config, error)
	authzClient         authz.Client
	idClient            auth.Resolver
	cryptoEngine        crypto.Engine
	restClientCache     ratecache.RestClientCache
	featureFlags        openfeature.IClient
	// We may want to start breaking up the server struct if we use it to
	// inject more entity-specific interfaces. For example, we may want to
	// consider having a struct per grpc service
	ruleTypes           ruletypes.RuleTypeService
	repos               github.RepositoryService
	profiles            profiles.ProfileService
	ghProviders         service.GitHubProviderService
	providerStore       providers.ProviderStore
	ghClient            ghprov.ClientService
	fallbackTokenClient *gh.Client
	providerManager     manager.ProviderManager
	projectCreator      projects.ProjectCreator
	projectDeleter      projects.ProjectDeleter

	// Implementations for service registration
	pb.UnimplementedHealthServiceServer
	pb.UnimplementedOAuthServiceServer
	pb.UnimplementedUserServiceServer
	pb.UnimplementedRepositoryServiceServer
	pb.UnimplementedProjectsServiceServer
	pb.UnimplementedProfileServiceServer
	pb.UnimplementedArtifactServiceServer
	pb.UnimplementedPermissionsServiceServer
	pb.UnimplementedProvidersServiceServer
	pb.UnimplementedEvalResultsServiceServer
}

// ServerOption is a function that modifies a server
type ServerOption func(*Server)

// WithProviderMetrics sets the provider metrics for the server
func WithProviderMetrics(mt provtelemetry.ProviderMetrics) ServerOption {
	return func(s *Server) {
		s.provMt = mt
	}
}

// WithAuthzClient sets the authz client for the server
func WithAuthzClient(c authz.Client) ServerOption {
	return func(s *Server) {
		s.authzClient = c
	}
}

// WithRestClientCache sets the rest client cache for the server
func WithRestClientCache(c ratecache.RestClientCache) ServerOption {
	return func(s *Server) {
		s.restClientCache = c
	}
}

// WithIdentityClient sets the identity client for the server
func WithIdentityClient(c *auth.IdentityClient) ServerOption {
	return func(s *Server) {
		s.idClient = c
	}
}

// WithServerMetrics sets the server metrics for the server
func WithServerMetrics(mt metrics.Metrics) ServerOption {
	return func(s *Server) {
		s.mt = mt
	}
}

// NewServer creates a new server instance
func NewServer(
	store db.Store,
	evt events.Publisher,
	cfg *serverconfig.Config,
	vldtr auth.JwtValidator,
	restCacheClient ratecache.RestClientCache,
	providerStore providers.ProviderStore,
	opts ...ServerOption,
) (*Server, error) {
	eng, err := crypto.EngineFromAuthConfig(&cfg.Auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto engine: %w", err)
	}

	whManager := webhooks.NewWebhookManager(cfg.WebhookConfig)
	profileSvc := profiles.NewProfileService(evt)
	mt := metrics.NewNoopMetrics()
	provMt := provtelemetry.NewNoopMetrics()
	ghClientFactory := clients.NewGitHubClientFactory(provMt)
	ruleSvc := ruletypes.NewRuleTypeService()
	marketplace, err := marketplaces.NewMarketplaceFromServiceConfig(cfg.Marketplace, profileSvc, ruleSvc)
	if err != nil {
		return nil, fmt.Errorf("failed to create marketplace: %w", err)
	}
	fallbackTokenClient := ghprov.NewFallbackTokenClient(cfg.Provider)

	s := &Server{
		store:               store,
		cfg:                 cfg,
		evt:                 evt,
		cryptoEngine:        eng,
		vldtr:               vldtr,
		providerAuthFactory: auth.NewOAuthConfig,
		mt:                  mt,
		provMt:              provMt,
		profiles:            profileSvc,
		ruleTypes:           ruleSvc,
		providerStore:       providerStore,
		featureFlags:        openfeature.NewClient(cfg.Flags.AppName),
		ghClient:            &ghprov.ClientServiceImplementation{},
		fallbackTokenClient: fallbackTokenClient,
		restClientCache:     restCacheClient,
		// TODO: this currently always returns authorized as a transitionary measure.
		// When OpenFGA is fully rolled out, we may want to make this a hard error or set to false.
		authzClient: &mock.NoopClient{Authorized: true},
		// TODO: an empty IdentityClient has no way to look up identities.  This means
		// callers need to supply WithIdentityClient() to the constructor.  It would be nice
		// to have a better way to do this.
		idClient: &auth.IdentityClient{},
	}

	for _, opt := range opts {
		opt(s)
	}

	// Moved after opts because it depends on the authz client
	// This will be cleaned up in the next PR
	s.projectCreator = projects.NewProjectCreator(s.authzClient, marketplace, &cfg.DefaultProfiles)

	projectFactory := makeProjectFactory(s.projectCreator, cfg.Identity)
	// TODO: Now that RestCacheClient is passed around directly, this will be
	// cleaned up in a future PR.
	// Moved here because we have a dependency on s.restClientCache
	s.ghProviders = service.NewGithubProviderService(
		store,
		eng,
		mt,
		provMt,
		&cfg.Provider,
		projectFactory,
		s.restClientCache,
		s.fallbackTokenClient,
	)

	githubProviderManager := ghmanager.NewGitHubProviderClassManager(
		s.restClientCache,
		ghClientFactory,
		&cfg.Provider,
		fallbackTokenClient,
		eng,
		whManager,
		store,
		s.ghProviders,
	)
	providerManager, err := manager.NewProviderManager(providerStore, githubProviderManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider manager: %w", err)
	}
	s.providerManager = providerManager
	s.projectDeleter = projects.NewProjectDeleter(s.authzClient, providerManager)
	s.repos = github.NewRepositoryService(whManager, store, evt, providerManager)

	return s, nil
}

// GetProjectDeleter returns the project deleter
// TODO: this will be removed in the next PR
func (s *Server) GetProjectDeleter() projects.ProjectDeleter {
	return s.projectDeleter
}

// GetProviderService returns the provider service
func (s *Server) GetProviderService() service.GitHubProviderService {
	return s.ghProviders
}

// GetAuthzClient returns the authz client
func (s *Server) GetAuthzClient() authz.Client {
	return s.authzClient
}

func (s *Server) initTracer() (*sdktrace.TracerProvider, error) {
	// create a stdout exporter to show collected spans out to stdout.
	exporter, err := stdout.New(stdout.WithPrettyPrint())
	if err != nil {
		return nil, err
	}
	sample_ratio := s.cfg.Tracing.SampleRatio
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sample_ratio))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp, nil
}

func initMetrics(r sdkmetric.Reader) *sdkmetric.MeterProvider {
	// See the go.opentelemetry.io/otel/sdk/resource package for more
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("minder"),
		// TODO: Make this auto-generated
		semconv.ServiceVersion("v0.1.0"),
	)
	// By default/spec (?!), otel includes net.sock.peer.{addr,port}.
	// See https://github.com/open-telemetry/opentelemetry-go-contrib/issues/3071
	// This exposes a DoS vector and needlessly blows up the RPC metrics.
	// This view filters the peer address and port out of the metrics.
	rpcPeerFilter := sdkmetric.NewView(
		sdkmetric.Instrument{Scope: instrumentation.Scope{
			Name: "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc",
		}},
		sdkmetric.Stream{AttributeFilter: attribute.NewDenyKeysFilter(
			"net.sock.peer.addr", "net.sock.peer.port",
		)},
	)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(r),
		sdkmetric.WithView(rpcPeerFilter),
	)

	otel.SetMeterProvider(mp)

	return mp
}

// StartGRPCServer starts a gRPC server and blocks while serving.
func (s *Server) StartGRPCServer(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.GRPCServer.GetAddress())
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	// add logger and tracing (if enabled)
	interceptors := []grpc.UnaryServerInterceptor{
		// TODO: this has no test coverage!
		util.SanitizingInterceptor(),
		logger.Interceptor(s.cfg.LoggingConfig),
		TokenValidationInterceptor,
		EntityContextProjectInterceptor,
		ProjectAuthorizationInterceptor,
	}

	options := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
		grpc.ChainUnaryInterceptor(interceptors...),
	}

	otelGRPCOpts := s.getOTELGRPCInterceptorOpts()
	if len(otelGRPCOpts) > 0 {
		options = append(options, grpc.StatsHandler(otelgrpc.NewServerHandler()))
	}

	s.grpcServer = grpc.NewServer(
		options...,
	)

	// register the services (declared within register_handlers.go)
	RegisterGRPCServices(s)

	reflection.Register(s.grpcServer)

	errch := make(chan error)

	log.Printf("Starting gRPC server on %s", s.cfg.GRPCServer.GetAddress())

	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			errch <- fmt.Errorf("failed to serve: %w", err)
		}
	}()

	select {
	case err := <-errch:
		log.Printf("GRPC server fatal error: %v\n", err)
		return err
	case <-ctx.Done():
		log.Printf("shutting down 'GRPC server'")
		s.grpcServer.GracefulStop()
		return nil
	}
}

// getOTELGRPCInterceptorOpts gathers relevant options and
func (s *Server) getOTELGRPCInterceptorOpts() []otelgrpc.Option {
	opts := []otelgrpc.Option{}
	if s.cfg.Tracing.Enabled {
		opts = append(opts, otelgrpc.WithTracerProvider(otel.GetTracerProvider()))
	}

	if s.cfg.Metrics.Enabled {
		opts = append(opts, otelgrpc.WithMeterProvider(otel.GetMeterProvider()))
	}

	return opts
}

// StartHTTPServer starts a HTTP server and registers the gRPC handler mux to it
// set store as a blank identifier for now as we will use it in the future
func (s *Server) StartHTTPServer(ctx context.Context) error {

	mux := http.NewServeMux()

	addTracing := s.cfg.Tracing.Enabled

	if addTracing {
		tp, err := s.initTracer()
		if err != nil {
			return fmt.Errorf("failed to initialize TracerProvider: %w", err)
		}
		defer shutdownHandler("TracerProvider", func(ctx context.Context) error {
			return tp.Shutdown(ctx)
		})
	}

	gwmux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	// register the services (declared within register_handlers.go)
	RegisterGatewayHTTPHandlers(ctx, gwmux, s.cfg.GRPCServer.GetAddress(), opts)

	fs := http.FileServer(http.FS(assets.StaticAssets))

	mw := otelhttp.NewMiddleware("webhook")

	// Explicitly handle HTTP only requests
	err := gwmux.HandlePath(http.MethodGet, "/api/v1/auth/callback/{provider}/cli", s.HandleOAuthCallback())
	if err != nil {
		return fmt.Errorf("failed to register provider callback handler: %w", err)
	}
	err = gwmux.HandlePath(http.MethodGet, "/api/v1/auth/callback/{provider}/web", s.HandleOAuthCallback())
	if err != nil {
		return fmt.Errorf("failed to register provider callback handler: %w", err)
	}
	err = gwmux.HandlePath(http.MethodGet, "/api/v1/auth/callback/{provider}/app", s.HandleGitHubAppCallback())
	if err != nil {
		return fmt.Errorf("failed to register GitHub App callback handler: %w", err)
	}

	mux.Handle("/", s.handlerWithHTTPMiddleware(gwmux))
	mux.Handle("/api/v1/webhook/", mw(s.HandleGitHubWebHook()))
	mux.Handle("/api/v1/ghapp/", mw(s.HandleGitHubAppWebhook()))
	mux.Handle("/api/v1/gh-marketplace/", mw(s.NoopWebhookHandler()))
	mux.Handle("/static/", fs)

	errch := make(chan error)

	log.Printf("Starting HTTP server on %s", s.cfg.HTTPServer.GetAddress())

	server := http.Server{
		Addr:              s.cfg.HTTPServer.GetAddress(),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// start the metrics server if enabled
	if s.cfg.Metrics.Enabled {
		go func() {
			if err := s.startMetricServer(ctx); err != nil {
				log.Printf("failed to start metrics server: %v", err)
			}
		}()
	}

	// start the HTTP server
	go func() {
		if err := server.ListenAndServe(); err != nil {
			errch <- fmt.Errorf("failed to serve: %w", err)
		}
	}()

	select {
	case err := <-errch:
		log.Printf("HTTP server fatal error: %v", err)
		return err
	case <-ctx.Done():
		shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownRelease()

		log.Printf("shutting down 'HTTP server'")

		return server.Shutdown(shutdownCtx)
	}
}

func (s *Server) handlerWithHTTPMiddleware(h http.Handler) http.Handler {
	if s.cfg.HTTPServer.CORS.Enabled {
		var opts []handlers.CORSOption
		if len(s.cfg.HTTPServer.CORS.AllowOrigins) > 0 {
			opts = append(opts, handlers.AllowedOrigins(s.cfg.HTTPServer.CORS.AllowOrigins))
		}
		if len(s.cfg.HTTPServer.CORS.AllowMethods) > 0 {
			opts = append(opts, handlers.AllowedMethods(s.cfg.HTTPServer.CORS.AllowMethods))
		}
		if len(s.cfg.HTTPServer.CORS.AllowHeaders) > 0 {
			opts = append(opts, handlers.AllowedHeaders(s.cfg.HTTPServer.CORS.AllowHeaders))
		}
		if len(s.cfg.HTTPServer.CORS.ExposeHeaders) > 0 {
			opts = append(opts, handlers.ExposedHeaders(s.cfg.HTTPServer.CORS.ExposeHeaders))
		}
		if s.cfg.HTTPServer.CORS.AllowCredentials {
			opts = append(opts, handlers.AllowCredentials())
		}

		return handlers.CORS(opts...)(h)
	}

	return h
}

// startMetricServer starts a Prometheus metrics server and blocks while serving
func (s *Server) startMetricServer(ctx context.Context) error {
	// pull-based Prometheus exporter
	prometheusExporter, err := prometheus.New(
		prometheus.WithNamespace("minder"),
	)
	if err != nil {
		return fmt.Errorf("could not initialize metrics: %w", err)
	}

	mp := initMetrics(prometheusExporter)
	defer shutdownHandler("MeterProvider", func(ctx context.Context) error {
		return mp.Shutdown(ctx)
	})

	err = s.mt.Init(s.store)
	if err != nil {
		return fmt.Errorf("could not initialize instruments: %w", err)
	}

	handler := promhttp.Handler()
	mux := http.NewServeMux()
	mux.Handle(metricsPath, handler)

	ch := make(chan error)

	log.Printf("Starting metrics server on %s", s.cfg.MetricServer.GetAddress())

	server := http.Server{
		Addr:              s.cfg.MetricServer.GetAddress(),
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {
		ch <- server.ListenAndServe()
	}()

	select {
	case err := <-ch:
		log.Printf("Metric server fatal error: %v", err)
		return err
	case <-ctx.Done():
		shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownRelease()

		log.Printf("shutting down 'Metric server'")

		return server.Shutdown(shutdownCtx)
	}
}

type shutdowner func(context.Context) error

func shutdownHandler(component string, sdf shutdowner) {
	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownRelease()

	log.Printf("shutting down '%s'", component)

	if err := sdf(shutdownCtx); err != nil {
		log.Fatal().Msgf("error shutting down '%s': %+v", component, err)
	}
}

// makeProjectFactory creates a callback used for GitHub project creation.
// The callback is used to construct a project for a GitHub App installation which was
// created by a user through the app installation flow on GitHub.  The flow on GitHub
// cannot be tied back to a specific project, so we create a new project for the provider.
//
// This is a callback because we want to encapsulate components like identity,
// projectCreator and the like from the providers implementation.
func makeProjectFactory(
	projectCreator projects.ProjectCreator,
	identity serverconfig.IdentityConfigWrapper,
) service.ProjectFactory {
	return func(
		ctx context.Context,
		qtx db.Querier,
		name string,
		ghUser int64,
	) (*db.Project, error) {
		user, err := auth.GetUserForGitHubId(ctx, identity, ghUser)
		if err != nil {
			return nil, fmt.Errorf("error getting user for GitHub ID: %w", err)
		}
		// Ensure the user already exists in the database
		if _, err := qtx.GetUserBySubject(ctx, user); err != nil {
			return nil, fmt.Errorf("error getting user %s from database: %w", user, err)
		}

		topLevelProject, err := projectCreator.ProvisionSelfEnrolledProject(
			ctx,
			qtx,
			name,
			user,
		)
		if err != nil {
			return nil, fmt.Errorf("error creating project: %w", err)
		}
		return topLevelProject, nil
	}
}
