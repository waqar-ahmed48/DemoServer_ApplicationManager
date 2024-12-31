package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"DemoServer_ApplicationManager/configuration"
	"DemoServer_ApplicationManager/datalayer"
	"DemoServer_ApplicationManager/handlers"
	"DemoServer_ApplicationManager/otel"
	"DemoServer_ApplicationManager/secretsmanager"

	"github.com/go-openapi/runtime/middleware"
	"github.com/gorilla/mux"
	"github.com/ilyakaznacheev/cleanenv"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func main() {
	var cfg configuration.Config

	configPath := configuration.ProcessArgs(&cfg)

	// read configuration from the file and environment variables
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

	/*if _, err := os.Stat(cfg.Configuration.Log_Folder); err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(cfg.Configuration.Log_Folder, 0700)

			if err != nil {
				fmt.Println(err)
				os.Exit(2)
			}
		} else {
			fmt.Println(err)
			os.Exit(2)
		}
	}

	file, err := os.OpenFile(cfg.Configuration.Log_Folder+"/"+cfg.Configuration.Log_File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	defer file.Close()*/

	w := io.MultiWriter(os.Stdout)

	loggerOpts := &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelDebug,
		/*ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				s := a.Value.Any().(*slog.Source)
				s.File = path.Base(s.File)
			}
			return a
		},*/
	}

	sl := slog.New(slog.NewJSONHandler(w, loggerOpts))

	logAttrGroup := slog.Group(
		"common",
		"service_name", cfg.Server.PrefixMain)

	l := sl.With(logAttrGroup)
	slog.SetDefault(l)

	r := mux.NewRouter()

	// Handle SIGINT (CTRL+C) gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	otlpHandler, otelShutdown, err := otel.NewOTLPHandler(ctx, &cfg, l)
	if err != nil {
		l.Error("OTLPHandler initialization failed. Error: " + err.Error())
		os.Exit(2)
	}

	if otlpHandler == nil {
		l.Error("OTLPHandler initialization failed. ")
		os.Exit(2)
	}

	defer func() {
		err = errors.Join(err, otelShutdown(context.Background()))
	}()

	pd, err := datalayer.NewPostgresDataSource(&cfg, l)
	if err != nil {
		l.Error("PostgresDataSource initialization failed. Error: " + err.Error())
		os.Exit(2)
	}

	err = pd.AutoMigrate()
	if err != nil {
		l.Error("PostgresDataSource AutoMigration failed. Error: " + err.Error())
		os.Exit(2)
	}

	vh, err := secretsmanager.NewVaultHandler(&cfg, l)
	if err != nil {
		l.Error("Vault Handler initialization failed. Error: " + err.Error())
		os.Exit(2)
	}

	sh := handlers.NewStatusHandler(l, pd, &cfg)

	statusRouter := r.Methods(http.MethodGet).Subrouter()
	statusRouter.HandleFunc("/v1/applicationmgmt/status", sh.GetStatus)
	statusRouter.Use(otelhttp.NewMiddleware("GET /status"))

	ah, err := handlers.NewApplicationHandler(&cfg, l, pd, vh)
	if err != nil {
		l.Error("ApplicationsHandler initialization failed. Error: " + err.Error())
		os.Exit(2)
	}

	getAppRouter := r.Methods(http.MethodGet).Subrouter()
	getAppRouter.HandleFunc("/v1/applicationmgmt/applications", ah.GetApplications)
	getAppRouter.Use(otelhttp.NewMiddleware("GET /applications"))
	getAppRouter.Use(ah.MiddlewareValidateApplicationsGet)

	getAppRouterWithID := r.Methods(http.MethodGet).Subrouter()
	getAppRouterWithID.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}", ah.GetApplication)
	getAppRouterWithID.Use(otelhttp.NewMiddleware("GET /application"))
	getAppRouterWithID.Use(ah.MiddlewareValidateApplication)

	postAppRouter := r.Methods(http.MethodPost).Subrouter()
	postAppRouter.HandleFunc("/v1/applicationmgmt/application", ah.AddApplication)
	postAppRouter.Use(otelhttp.NewMiddleware("POST /application"))
	postAppRouter.Use(ah.MiddlewareValidateApplicationPost)

	patchAppRouter := r.Methods(http.MethodPatch).Subrouter()
	patchAppRouter.HandleFunc("/v1/applicationmgmt/application{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}", ah.UpdateApplication)
	patchAppRouter.Use(otelhttp.NewMiddleware("PATCH /application"))
	patchAppRouter.Use(ah.MiddlewareValidateApplicationUpdate)

	deleteAppRouter := r.Methods(http.MethodDelete).Subrouter()
	deleteAppRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}", ah.DeleteApplication)
	deleteAppRouter.Use(otelhttp.NewMiddleware("DELETE /application"))
	deleteAppRouter.Use(ah.MiddlewareValidateApplication)

	postPackageUploadRouter := r.Methods(http.MethodPost).Subrouter()
	postPackageUploadRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/package", ah.UploadPackage)
	postPackageUploadRouter.Use(otelhttp.NewMiddleware("POST /application/package"))
	postPackageUploadRouter.Use(ah.MiddlewareValidatePackageUpload)

	getPackageDownloadRouter := r.Methods(http.MethodGet).Subrouter()
	getPackageDownloadRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/package", ah.GetPackageLink)
	getPackageDownloadRouter.Use(otelhttp.NewMiddleware("POST /application/package"))
	getPackageDownloadRouter.Use(ah.MiddlewareValidatePackageDownload)

	listStateRouter := r.Methods(http.MethodGet).Subrouter()
	listStateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/state/resource", ah.ListState)
	listStateRouter.Use(otelhttp.NewMiddleware("GET /application/state"))
	listStateRouter.Use(ah.MiddlewareValidateListState)

	moveStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	moveStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/state/move", ah.MoveStateResource)
	moveStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/state/move"))
	moveStateResourceRouter.Use(ah.MiddlewareValidateMoveStateResource)

	removeStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	removeStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/state/remove", ah.RemoveStateResource)
	removeStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/state/remove"))
	removeStateResourceRouter.Use(ah.MiddlewareValidateRemoveStateResource)

	importStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	importStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/state/import", ah.ImportStateResource)
	importStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/state/import"))
	importStateResourceRouter.Use(ah.MiddlewareValidateImportStateResource)

	listModulesRouter := r.Methods(http.MethodGet).Subrouter()
	listModulesRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/module", ah.ListModules)
	listModulesRouter.Use(otelhttp.NewMiddleware("GET /application/modules"))
	listModulesRouter.Use(ah.MiddlewareValidateListModules)

	installModuleRouter := r.Methods(http.MethodPost).Subrouter()
	installModuleRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/module/install", ah.InstallModule)
	installModuleRouter.Use(otelhttp.NewMiddleware("POST /application/module/install"))
	installModuleRouter.Use(ah.MiddlewareValidateInstallModule)

	getTofuWorkspaceRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/workspaces", ah.GetTofuWorkspaces)
	getTofuWorkspaceRouter.Use(otelhttp.NewMiddleware("GET /application/tofu/workspaces"))
	getTofuWorkspaceRouter.Use(ah.MiddlewareValidateGetTofuWorkspaces)

	postTofuWorkspaceRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/workspace", ah.AddTofuWorkspace)
	postTofuWorkspaceRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/workspace"))
	postTofuWorkspaceRouter.Use(ah.MiddlewareValidatePostTofuWorkspace)

	postTofuWorkspaceSwitchRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuWorkspaceSwitchRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/workspace/switch", ah.SwitchTofuWorkspace)
	postTofuWorkspaceSwitchRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/workspace/switch"))
	postTofuWorkspaceSwitchRouter.Use(ah.MiddlewareValidateTofuWorkspaceSwitch)

	getTofuGraphRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuGraphRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/graph", ah.TofuGraph)
	getTofuGraphRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/graph"))
	getTofuGraphRouter.Use(ah.MiddlewareValidateTofuGraph)

	getTofuOutputRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuOutputRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/output", ah.TofuOutput)
	getTofuOutputRouter.Use(otelhttp.NewMiddleware("GET /application/tofu/output"))
	getTofuOutputRouter.Use(ah.MiddlewareValidateTofuOutput)

	getTofuVersionRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuVersionRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/version", ah.TofuVersion)
	getTofuVersionRouter.Use(otelhttp.NewMiddleware("GET /application/tofu/version"))
	getTofuVersionRouter.Use(ah.MiddlewareValidateTofuVersion)

	getTGVersionRouter := r.Methods(http.MethodGet).Subrouter()
	getTGVersionRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/version", ah.TGVersion)
	getTGVersionRouter.Use(otelhttp.NewMiddleware("GET /application/terragrunt/version"))
	getTGVersionRouter.Use(ah.MiddlewareValidateTGVersion)

	getTGRenderRouter := r.Methods(http.MethodGet).Subrouter()
	getTGRenderRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/render", ah.TGRender)
	getTGRenderRouter.Use(otelhttp.NewMiddleware("GET /application/terragrunt/render"))
	getTGRenderRouter.Use(ah.MiddlewareValidateTGRender)

	getTGInfoRouter := r.Methods(http.MethodGet).Subrouter()
	getTGInfoRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/info", ah.TGInfo)
	getTGInfoRouter.Use(otelhttp.NewMiddleware("GET /application/terragrunt/render"))
	getTGInfoRouter.Use(ah.MiddlewareValidateTGInfo)

	getTGOutputRouter := r.Methods(http.MethodGet).Subrouter()
	getTGOutputRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/info", ah.TGOutput)
	getTGOutputRouter.Use(otelhttp.NewMiddleware("GET /application/terragrunt/output"))
	getTGOutputRouter.Use(ah.MiddlewareValidateTGOutput)

	postTGDestroyRouter := r.Methods(http.MethodPost).Subrouter()
	postTGDestroyRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/destroy", ah.TGDestroy)
	postTGDestroyRouter.Use(otelhttp.NewMiddleware("POST /application/terragrunt/destroy"))
	postTGDestroyRouter.Use(ah.MiddlewareValidateTGDestroy)

	postTGApplyRouter := r.Methods(http.MethodPost).Subrouter()
	postTGApplyRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/apply", ah.TGApply)
	postTGApplyRouter.Use(otelhttp.NewMiddleware("POST /application/terragrunt/apply"))
	postTGApplyRouter.Use(ah.MiddlewareValidateTGApply)

	postTGPlanRouter := r.Methods(http.MethodPost).Subrouter()
	postTGPlanRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/plan", ah.TGPlan)
	postTGPlanRouter.Use(otelhttp.NewMiddleware("POST /application/terragrunt/destroy"))
	postTGPlanRouter.Use(ah.MiddlewareValidateTGPlan)

	postTGValidateRouter := r.Methods(http.MethodPost).Subrouter()
	postTGValidateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/validate", ah.TGValidate)
	postTGValidateRouter.Use(otelhttp.NewMiddleware("POST /application/terragrunt/validate"))
	postTGValidateRouter.Use(ah.MiddlewareValidateTGValidate)

	postTGInitRouter := r.Methods(http.MethodPost).Subrouter()
	postTGInitRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/terragrunt/init", ah.TGInit)
	postTGInitRouter.Use(otelhttp.NewMiddleware("POST /application/terragrunt/init"))
	postTGInitRouter.Use(ah.MiddlewareValidateTGInit)

	opts := middleware.RedocOpts{SpecURL: "/swagger.yaml"}
	docs_sh := middleware.Redoc(opts, nil)

	docsRouter := r.Methods(http.MethodGet).Subrouter()
	docsRouter.Use(otelhttp.NewMiddleware("GET /docs"))
	docsRouter.Handle("/docs", docs_sh)
	docsRouter.Handle("/swagger.yaml", http.FileServer(http.Dir("./")))

	s := http.Server{
		Addr:         ":" + strconv.Itoa(cfg.Server.Port),
		Handler:      r,
		IdleTimeout:  time.Duration(cfg.Server.HTTPIdleTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.HTTPWriteTimeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.Server.HTTPReadTimeout) * time.Second,
	}

	go func() {
		l.Info("Started listening", slog.Int("port", cfg.Server.Port))

		err := s.ListenAndServe()
		if err != nil {
			l.Info(err.Error())
			// os.Exit(0)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	signal.Notify(sigChan, syscall.SIGTERM)

	sig := <-sigChan
	l.Info("Terminal request received. Initiating Graceful shutdown", "signal", sig.String())

	tc, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.HTTPShutdownTimeout)*time.Second)
	defer cancel()
	l.Info("New requests processing stopped.")

	err = s.Shutdown(tc)
	if err != nil {
		l.Error("Connections Handler initialization failed. Error: " + err.Error())
	}
}
