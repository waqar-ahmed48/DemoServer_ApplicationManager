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

	ah, err := handlers.NewApplicationsHandler(&cfg, l, pd, vh)
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
	deleteAppRouter.Use(ah.MiddlewareValidateAWSConnection)

	postTofuPackageUploadRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuPackageUploadRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/package", ah.TofuUploadPackage)
	postTofuPackageUploadRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/package"))
	postTofuPackageUploadRouter.Use(ah.MiddlewareValidateTofuPackageUpload)

	getTofuPackageDownloadRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuPackageDownloadRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/package", ah.TofuDownloadPackage)
	getTofuPackageDownloadRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/package"))
	getTofuPackageDownloadRouter.Use(ah.MiddlewareValidateTofuPackageDownload)

	postTofuPackagePackRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuPackagePackRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/package/pack", ah.TofuPackPackage)
	postTofuPackagePackRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/package/pack"))
	postTofuPackagePackRouter.Use(ah.MiddlewareValidateTofuPackagePack)

	postTofuPackageUnpackRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuPackageUnpackRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/package/unpack", ah.TofuUnpackPackage)
	postTofuPackageUnpackRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/package/unpack"))
	postTofuPackageUnpackRouter.Use(ah.MiddlewareValidateTofuPackageUnpack)

	postTofuInitkRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuInitkRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/init", ah.TofuInit)
	postTofuInitkRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/init"))
	postTofuInitkRouter.Use(ah.MiddlewareValidateTofuInit)

	postTofuValidateRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuValidateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/validate", ah.TofuValidate)
	postTofuValidateRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/validate"))
	postTofuValidateRouter.Use(ah.MiddlewareValidateTofuValidate)

	postTofuPlanRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuPlanRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/plan", ah.TofuPlan)
	postTofuPlanRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/plan"))
	postTofuPlanRouter.Use(ah.MiddlewareValidateTofuPlan)

	postTofuApplyRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuApplyRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/apply", ah.TofuApply)
	postTofuApplyRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/apply"))
	postTofuApplyRouter.Use(ah.MiddlewareValidateTofuApply)

	postTofuDestroyRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuDestroyRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/destroy", ah.TofuDestroy)
	postTofuDestroyRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/destroy"))
	postTofuDestroyRouter.Use(ah.MiddlewareValidateTofuDestroy)

	getTofuShowRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuShowRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/plan", ah.TofuPlan)
	getTofuShowRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/plan"))
	getTofuShowRouter.Use(ah.MiddlewareValidateTofuPlan)

	getTofuStateRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuStateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/state", ah.TofuState)
	getTofuStateRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/state"))
	getTofuStateRouter.Use(ah.MiddlewareValidateTofuState)

	deleteTofuStateResourceRouter := r.Methods(http.MethodDelete).Subrouter()
	deleteTofuStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/state/resource", ah.DeleteTofuStateResource)
	deleteTofuStateResourceRouter.Use(otelhttp.NewMiddleware("DELETE /application/tofu/state/resource"))
	deleteTofuStateResourceRouter.Use(ah.MiddlewareValidateDeleteTofuStateResource)

	postTofuStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/state/resource", ah.AddTofuStateResource)
	postTofuStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/state/resource"))
	postTofuStateResourceRouter.Use(ah.MiddlewareValidatePostTofuStateResource)

	postTofuModuleRouter := r.Methods(http.MethodPost).Subrouter()
	postTofuModuleRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$}/tofu/module", ah.TofuModule)
	postTofuModuleRouter.Use(otelhttp.NewMiddleware("POST /application/tofu/module"))
	postTofuModuleRouter.Use(ah.MiddlewareValidatePostTofuModule)

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
