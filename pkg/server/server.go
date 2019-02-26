package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/hellofresh/janus/pkg/api"
	"github.com/hellofresh/janus/pkg/config"
	"github.com/hellofresh/janus/pkg/errors"
	"github.com/hellofresh/janus/pkg/loader"
	"github.com/hellofresh/janus/pkg/middleware"
	"github.com/hellofresh/janus/pkg/plugin"
	"github.com/hellofresh/janus/pkg/proxy"
	"github.com/hellofresh/janus/pkg/router"
	"github.com/hellofresh/janus/pkg/web"
	"github.com/hellofresh/stats-go/client"
	log "github.com/sirupsen/logrus"
)

// Server is the Janus server
type Server struct {
	server                *http.Server
	provider              api.Repository
	register              *proxy.Register
	apiLoader             *loader.APILoader
	currentConfigurations *api.Configuration
	configurationChan     chan api.ConfigurationChanged
	stopChan              chan struct{}
	globalConfig          *config.Specification
	statsClient           client.Client
	webServer             *web.Server
	profilingEnabled      bool
	profilingPublic       bool
	currentTargets        currentTargets
}

// New creates a new instance of Server
func New(opts ...Option) *Server {
	s := Server{
		configurationChan: make(chan api.ConfigurationChanged, 100),
		stopChan:          make(chan struct{}, 1),
		currentTargets:    currentTargets{Targets: make(map[string]*targetsEvent)},
	}

	for _, opt := range opts {
		opt(&s)
	}

	return &s
}

type currentTargets struct {
	sync.Mutex
	Targets map[string]*targetsEvent
}

// Start starts the server
func (s *Server) Start() error {
	return s.StartWithContext(context.Background())
}

// StartWithContext starts the server and Stop/Close it when context is Done
func (s *Server) StartWithContext(ctx context.Context) error {
	go func() {
		defer s.Close()
		<-ctx.Done()
		log.Info("I have to go...")
		reqAcceptGraceTimeOut := time.Duration(s.globalConfig.GraceTimeOut)
		if reqAcceptGraceTimeOut > 0 {
			log.Infof("Waiting %s for incoming requests to cease", reqAcceptGraceTimeOut)
			time.Sleep(reqAcceptGraceTimeOut)
		}
		log.Info("Stopping server gracefully")
	}()

	// Register must be initialised synchronously to avoid race condition
	r := s.createRouter()
	s.register = proxy.NewRegister(
		proxy.WithRouter(r),
		proxy.WithFlushInterval(s.globalConfig.BackendFlushInterval),
		proxy.WithIdleConnectionsPerHost(s.globalConfig.MaxIdleConnsPerHost),
		proxy.WithIdleConnTimeout(s.globalConfig.IdleConnTimeout),
		proxy.WithStatsClient(s.statsClient),
	)

	// API Loader must be initialised synchronously as well to avoid race condition
	s.apiLoader = loader.NewAPILoader(s.register)

	go func() {
		if err := s.startHTTPServers(ctx, r); err != nil {
			log.WithError(err).Fatal("Could not start http servers")
		}
	}()

	go s.listenProviders(s.stopChan)

	definitions, err := s.provider.FindAll()
	if err != nil {
		return errors.Wrap(err, "could not find all configurations from the provider")
	}

	s.currentConfigurations = &api.Configuration{Definitions: definitions}
	if err := s.startProvider(ctx); err != nil {
		log.WithError(err).Fatal("Could not start providers")
	}

	event := plugin.OnStartup{
		StatsClient:   s.statsClient,
		Register:      s.register,
		Config:        s.globalConfig,
		Configuration: definitions,
	}

	if mgoRepo, ok := s.provider.(*api.MongoRepository); ok {
		event.MongoSession = mgoRepo.Session
	}

	plugin.EmitEvent(plugin.StartupEvent, event)
	s.apiLoader.RegisterAPIs(definitions)

	log.Info("Janus started")

	go func() {
		for {
			s.refreshTargets()
			time.Sleep(s.globalConfig.TargetsChecker.SleepPeriod)
		}
	}()

	return nil
}

// Wait blocks until server is shut down.
func (s *Server) Wait() {
	<-s.stopChan
}

// Stop stops the server
func (s *Server) Stop() {
	defer log.Info("Server stopped")

	graceTimeOut := time.Duration(s.globalConfig.GraceTimeOut)
	ctx, cancel := context.WithTimeout(context.Background(), graceTimeOut)
	defer cancel()
	log.Debugf("Waiting %s seconds before killing connections...", graceTimeOut)
	if err := s.server.Shutdown(ctx); err != nil {
		log.WithError(err).Debug("Wait is over due to error")
		s.server.Close()
	}
	log.Debug("Server closed")

	s.stopChan <- struct{}{}
}

// Close closes the server
func (s *Server) Close() error {
	defer close(s.stopChan)
	defer close(s.configurationChan)
	defer s.webServer.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func(ctx context.Context) {
		<-ctx.Done()
		if ctx.Err() == context.Canceled {
			return
		} else if ctx.Err() == context.DeadlineExceeded {
			panic("Timeout while stopping janus, killing instance ✝")
		}
	}(ctx)

	return s.server.Close()
}

func (s *Server) startHTTPServers(ctx context.Context, r router.Router) error {
	return s.listenAndServe(chi.ServerBaseContext(ctx, r))
}

func (s *Server) startProvider(ctx context.Context) error {
	s.webServer = web.New(
		web.WithConfigurations(s.currentConfigurations),
		web.WithPort(s.globalConfig.Web.Port),
		web.WithTLS(s.globalConfig.Web.TLS),
		web.WithCredentials(s.globalConfig.Web.Credentials),
		web.WithProfiler(s.profilingEnabled, s.profilingPublic),
	)

	if err := s.webServer.Start(); err != nil {
		return errors.Wrap(err, "could not start Janus web API")
	}

	// We're listening to the configuration changes in any case, even if provider does not implement Listener,
	// so we can use "file" storage as memory - all the persistent definitions are loaded on startup,
	// but then API allows to manipulate proxies in memory. Otherwise api calls just stuck because channel is busy.
	go func() {
		ch := make(chan api.ConfigurationMessage)
		listener, providerIsListener := s.provider.(api.Listener)
		if providerIsListener {
			listener.Listen(ctx, ch)
		}

		for {
			select {
			case c, more := <-s.webServer.ConfigurationChan:
				if !more {
					return
				}
				if c.Operation == api.RemovedOperation {
					log.Debug(fmt.Sprintf("configuration channel send remove operation for definition. Name: %s Surname: %s", c.Configuration.Name, c.Configuration.Surname))
				}

				s.updateConfigurations(c)
				s.handleEvent(s.currentConfigurations)

				if providerIsListener {
					ch <- c
				}
			case <-ctx.Done():
				close(ch)
				return
			}
		}
	}()

	if watcher, ok := s.provider.(api.Watcher); ok {
		watcher.Watch(ctx, s.configurationChan)
	}

	return nil
}

func (s *Server) listenProviders(stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case configMsg, ok := <-s.configurationChan:
			if !ok {
				return
			}
			if len(configMsg.Configurations.Definitions) == 0 {
				log.Debug("config message with empty definition array received")
			}

			if s.currentConfigurations.EqualsTo(configMsg.Configurations) {
				log.Debug("Skipping same configuration")
				continue
			}

			s.currentConfigurations.Definitions = configMsg.Configurations.Definitions
			s.handleEvent(configMsg.Configurations)
		}
	}
}

func (s *Server) listenAndServe(handler http.Handler) error {
	address := fmt.Sprintf(":%v", s.globalConfig.Port)
	logger := log.WithField("address", address)
	s.server = &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  s.globalConfig.RespondingTimeouts.ReadTimeout,
		WriteTimeout: s.globalConfig.RespondingTimeouts.WriteTimeout,
		IdleTimeout:  s.globalConfig.RespondingTimeouts.IdleTimeout,
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrap(err, "error opening listener")
	}

	if s.globalConfig.TLS.IsHTTPS() {
		s.server.Addr = fmt.Sprintf(":%v", s.globalConfig.TLS.Port)

		if s.globalConfig.TLS.Redirect {
			go func() {
				logger.Info("Listening HTTP redirects to HTTPS")
				log.Fatal(http.Serve(listener, web.RedirectHTTPS(s.globalConfig.TLS.Port)))
			}()
		}

		logger.Info("Listening HTTPS")
		return s.server.ServeTLS(listener, s.globalConfig.TLS.CertFile, s.globalConfig.TLS.KeyFile)
	}

	logger.Info("Certificate and certificate key were not found, defaulting to HTTP")
	return s.server.Serve(listener)
}

func (s *Server) createRouter() router.Router {
	// create router with a custom not found handler
	router.DefaultOptions.NotFoundHandler = errors.NotFound
	r := router.NewChiRouterWithOptions(router.DefaultOptions)

	// Add RequestID middleware first if enabled, so we could use it in other middlewares, e.g. logger
	if s.globalConfig.RequestID {
		r.Use(middleware.RequestID)
	}

	r.Use(
		middleware.NewStats(s.statsClient).Handler,
		middleware.NewLogger().Handler,
		middleware.NewRecovery(errors.RecoveryHandler),
	)

	// some routers may panic when have empty routes list, so add one dummy 404 route to avoid this
	if r.RoutesCount() < 1 {
		r.Any("/", errors.NotFound)
	}

	return r
}

func (s *Server) updateConfigurations(cfg api.ConfigurationMessage) {
	currentDefinitions := s.currentConfigurations.Definitions

	switch cfg.Operation {
	case api.AddedOperation:
		currentDefinitions = append(currentDefinitions, cfg.Configuration)
	case api.UpdatedOperation:
		for i, d := range currentDefinitions {
			if d.Name == cfg.Configuration.Name {
				currentDefinitions[i] = cfg.Configuration
			}
		}
	case api.RemovedOperation:
		for i, d := range currentDefinitions {
			if d.Name == cfg.Configuration.Name {
				copy(currentDefinitions[i:], currentDefinitions[i+1:])
				// currentDefinitions[len(currentDefinitions)-1] = nil // or the zero value of T
				currentDefinitions = currentDefinitions[:len(currentDefinitions)-1]
			}
		}
	}

	s.currentConfigurations.Definitions = currentDefinitions
	// update currentTargets with all kinds of definitions updates
	s.updateTargets()
}

func (s *Server) handleEvent(cfg *api.Configuration) {
	log.Debug("Refreshing configuration")
	newRouter := s.createRouter()

	s.register.UpdateRouter(newRouter)
	s.apiLoader.RegisterAPIs(cfg.Definitions)

	plugin.EmitEvent(plugin.ReloadEvent, plugin.OnReload{Configurations: cfg.Definitions})

	s.server.Handler = newRouter
	log.Debug("Configuration refresh done")
}

type targetsEvent struct {
	Targets  []*proxy.Target
	Attempts int
	Weight   int
}

func (s *Server) refreshTargets() {
	s.currentTargets.Lock()
	defer s.currentTargets.Unlock()

	// check health for all targets in currentTargets and change weights if needed
	for url, event := range s.currentTargets.Targets {
		resp, err := doStatusRequest(url, true)
		if err != nil || resp.StatusCode >= http.StatusInternalServerError {
			event.Weight = 0
			event.Attempts++
			for _, target := range event.Targets {
				target.Weight = 0
			}

			// if target weight were zero for too long - delete from all definitions
			if event.Attempts >= s.globalConfig.TargetsChecker.Attempts {
				log.Info(fmt.Sprintf("target %s removed after %d attempts", url, s.globalConfig.TargetsChecker.Attempts))
				s.removeFromDefs(url)
				delete(s.currentTargets.Targets, url)
			}

			log.Info(fmt.Sprintf("unhealthy target %s after %d attempts", url, event.Attempts))
			continue
		}

		// if target working again - refresh weights
		if event.Weight <= 0 {
			for _, target := range event.Targets {
				target.Weight = 10
			}
			event.Weight = 10
			event.Attempts = 0
		}
	}
}

func doStatusRequest(target string, closeBody bool) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}

	if closeBody {
		defer resp.Body.Close()
	}

	return resp, err
}

func (s *Server) removeFromDefs(targetURL string) {
	for _, def := range s.currentConfigurations.Definitions {
		for i, target := range def.Proxy.Upstreams.Targets {
			if target.Target == targetURL {
				def.Proxy.Upstreams.Targets = append(def.Proxy.Upstreams.Targets[:i], def.Proxy.Upstreams.Targets[i+1:]...)
			}
		}
	}
}

func (s *Server) updateTargets() {
	s.currentTargets.Lock()
	defer s.currentTargets.Unlock()

	s.currentTargets.Targets = make(map[string]*targetsEvent)
	for _, def := range s.currentConfigurations.Definitions {
		for _, trg := range def.Proxy.Upstreams.Targets {
			if _, ok := s.currentTargets.Targets[trg.Target]; !ok {
				s.currentTargets.Targets[trg.Target] = &targetsEvent{}
			}
			s.currentTargets.Targets[trg.Target].Targets = append(s.currentTargets.Targets[trg.Target].Targets, trg)
			s.currentTargets.Targets[trg.Target].Weight = trg.Weight
		}
	}
}
