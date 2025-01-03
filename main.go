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

	getAppsRouter := r.Methods(http.MethodGet).Subrouter()
	getAppsRouter.HandleFunc("/v1/applicationmgmt/applications", ah.GetApplications)
	getAppsRouter.Use(otelhttp.NewMiddleware("GET /applications"))
	getAppsRouter.Use(ah.MVApplicationsGet)

	getAppRouter := r.Methods(http.MethodGet).Subrouter()
	getAppRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}", ah.GetApplication)
	getAppRouter.Use(otelhttp.NewMiddleware("GET /application"))
	getAppRouter.Use(ah.MVApplication)

	postAppRouter := r.Methods(http.MethodPost).Subrouter()
	postAppRouter.HandleFunc("/v1/applicationmgmt/application", ah.AddApplication)
	postAppRouter.Use(otelhttp.NewMiddleware("POST /application"))
	postAppRouter.Use(ah.MVAddApplication)

	patchAppRouter := r.Methods(http.MethodPatch).Subrouter()
	patchAppRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}", ah.UpdateApplication)
	patchAppRouter.Use(otelhttp.NewMiddleware("PATCH /application"))
	patchAppRouter.Use(ah.MVApplicationUpdate)

	deleteAppRouter := r.Methods(http.MethodDelete).Subrouter()
	deleteAppRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}", ah.DeleteApplication)
	deleteAppRouter.Use(otelhttp.NewMiddleware("DELETE /application"))
	deleteAppRouter.Use(ah.MVApplication)

	getVersionsRouter := r.Methods(http.MethodGet).Subrouter()
	getVersionsRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/versions", ah.GetVersions)
	getVersionsRouter.Use(otelhttp.NewMiddleware("GET /application/versions"))
	getVersionsRouter.Use(ah.MVVersionsGet)

	getVersionRouter := r.Methods(http.MethodGet).Subrouter()
	getVersionRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}", ah.GetVersion)
	getVersionRouter.Use(otelhttp.NewMiddleware("GET /application/version"))
	getVersionRouter.Use(ah.MVVersion)

	createVersionRouter := r.Methods(http.MethodPost).Subrouter()
	createVersionRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version", ah.AddVersion)
	createVersionRouter.Use(otelhttp.NewMiddleware("POST /application/version/"))
	createVersionRouter.Use(ah.MVVersionPost)

	patchVersionRouter := r.Methods(http.MethodPatch).Subrouter()
	patchVersionRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}", ah.UpdateVersion)
	patchVersionRouter.Use(otelhttp.NewMiddleware("PATCH /application/version"))
	patchVersionRouter.Use(ah.MVVersionUpdate)

	setVersionStateRouter := r.Methods(http.MethodPost).Subrouter()
	setVersionStateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/state", ah.SetVersionState)
	setVersionStateRouter.Use(otelhttp.NewMiddleware("POST /application/version/state"))
	setVersionStateRouter.Use(ah.MVSetVersionState)

	queryAuditRouter := r.Methods(http.MethodGet).Subrouter()
	queryAuditRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/audit/query", ah.QueryAudit)
	queryAuditRouter.Use(otelhttp.NewMiddleware("GET /application/audit/query"))
	queryAuditRouter.Use(ah.MVQueryAudit)

	uploadPackageRouter := r.Methods(http.MethodPost).Subrouter()
	uploadPackageRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/package", ah.UploadPackage)
	uploadPackageRouter.Use(otelhttp.NewMiddleware("POST /application/version/package"))
	uploadPackageRouter.Use(ah.MVPackageUpload)

	lsPackageRouter := r.Methods(http.MethodGet).Subrouter()
	lsPackageRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/package/ls", ah.LSPackage)
	lsPackageRouter.Use(otelhttp.NewMiddleware("GET /application/version/package/ls"))
	lsPackageRouter.Use(ah.MVLSPackage)

	downloadPackageRouter := r.Methods(http.MethodGet).Subrouter()
	downloadPackageRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/package", ah.GetPackageLink)
	downloadPackageRouter.Use(otelhttp.NewMiddleware("GET /application/version/package"))
	downloadPackageRouter.Use(ah.MVGetPackageLink)

	listStateRouter := r.Methods(http.MethodGet).Subrouter()
	listStateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/state/resource", ah.ListState)
	listStateRouter.Use(otelhttp.NewMiddleware("GET /application/version/state/resource"))
	listStateRouter.Use(ah.MVListState)

	moveStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	moveStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/state/move", ah.MoveStateResource)
	moveStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/version/state/move"))
	moveStateResourceRouter.Use(ah.MVMoveStateResource)

	removeStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	removeStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/state/remove", ah.RemoveStateResource)
	removeStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/version/state/remove"))
	removeStateResourceRouter.Use(ah.MVRemoveStateResource)

	importStateResourceRouter := r.Methods(http.MethodPost).Subrouter()
	importStateResourceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/state/import", ah.ImportStateResource)
	importStateResourceRouter.Use(otelhttp.NewMiddleware("POST /application/version/state/import"))
	importStateResourceRouter.Use(ah.MVImportStateResource)

	listWorkspaceRouter := r.Methods(http.MethodGet).Subrouter()
	listWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/workspaces", ah.GetWorkspaces)
	listWorkspaceRouter.Use(otelhttp.NewMiddleware("GET /application/version/workspaces"))
	listWorkspaceRouter.Use(ah.MVGetWorkspaces)

	selectWorkspaceRouter := r.Methods(http.MethodPost).Subrouter()
	selectWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/workspace/select/{workspacename:[a-fA-F0-9]{20}}", ah.SelectWorkspace)
	selectWorkspaceRouter.Use(otelhttp.NewMiddleware("POST /application/version/workspace/select"))
	selectWorkspaceRouter.Use(ah.MVSelectWorkspace)

	showWorkspaceRouter := r.Methods(http.MethodGet).Subrouter()
	showWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/workspace/{workspacename:[a-fA-F0-9]{20}}", ah.ShowWorkspace)
	showWorkspaceRouter.Use(otelhttp.NewMiddleware("GET /application/version/workspace"))
	showWorkspaceRouter.Use(ah.MVShowWorkspace)

	deleteWorkspaceRouter := r.Methods(http.MethodDelete).Subrouter()
	deleteWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/workspace/{workspacename:[a-fA-F0-9]{20}}", ah.DeleteWorkspace)
	deleteWorkspaceRouter.Use(otelhttp.NewMiddleware("DELETE /application/version/workspace"))
	deleteWorkspaceRouter.Use(ah.MVDeleteWorkspace)

	createWorkspaceRouter := r.Methods(http.MethodPost).Subrouter()
	createWorkspaceRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/workspace", ah.CreateWorkspace)
	createWorkspaceRouter.Use(otelhttp.NewMiddleware("POST /application/version/workspace"))
	createWorkspaceRouter.Use(ah.MVCreateWorkspace)

	graphTofuRouter := r.Methods(http.MethodGet).Subrouter()
	graphTofuRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/tofu/graph", ah.GraphTofu)
	graphTofuRouter.Use(otelhttp.NewMiddleware("GET /application/version/tofu/graph"))
	graphTofuRouter.Use(ah.MVGraphTofu)

	outputRouter := r.Methods(http.MethodGet).Subrouter()
	outputRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/output", ah.Output)
	outputRouter.Use(otelhttp.NewMiddleware("GET /application/version/output"))
	outputRouter.Use(ah.MVOutput)

	refreshRouter := r.Methods(http.MethodPost).Subrouter()
	refreshRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/refresh", ah.Refresh)
	refreshRouter.Use(otelhttp.NewMiddleware("POST /application/version/refresh"))
	refreshRouter.Use(ah.MVRefresh)

	getTofuVersionRouter := r.Methods(http.MethodGet).Subrouter()
	getTofuVersionRouter.HandleFunc("/v1/applicationmgmt/tofu/version", ah.TofuVersion)
	getTofuVersionRouter.Use(otelhttp.NewMiddleware("GET /tofu/version"))
	getTofuVersionRouter.Use(ah.MVTofuVersion)

	getTGVersionRouter := r.Methods(http.MethodGet).Subrouter()
	getTGVersionRouter.HandleFunc("/v1/applicationmgmt/terragrunt/version", ah.TGVersion)
	getTGVersionRouter.Use(otelhttp.NewMiddleware("GET /terragrunt/version"))
	getTGVersionRouter.Use(ah.MVTGVersion)

	destroyRouter := r.Methods(http.MethodPost).Subrouter()
	destroyRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/destroy", ah.Destroy)
	destroyRouter.Use(otelhttp.NewMiddleware("POST /application/version/destroy"))
	destroyRouter.Use(ah.MVDestroy)

	applyRouter := r.Methods(http.MethodPost).Subrouter()
	applyRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/apply", ah.Apply)
	applyRouter.Use(otelhttp.NewMiddleware("POST /application/version/apply"))
	applyRouter.Use(ah.MVApply)

	planRouter := r.Methods(http.MethodPost).Subrouter()
	planRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/plan", ah.Plan)
	planRouter.Use(otelhttp.NewMiddleware("POST /application/version/plan"))
	planRouter.Use(ah.MVPlan)

	validateRouter := r.Methods(http.MethodPost).Subrouter()
	validateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/validate", ah.Validate)
	validateRouter.Use(otelhttp.NewMiddleware("POST /application/version/validate"))
	validateRouter.Use(ah.MVValidate)

	hclvalidateRouter := r.Methods(http.MethodPost).Subrouter()
	hclvalidateRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/hclvalidate", ah.HclValidate)
	hclvalidateRouter.Use(otelhttp.NewMiddleware("POST /application/version/hclvalidate"))
	hclvalidateRouter.Use(ah.MVHclValidate)

	initRouter := r.Methods(http.MethodPost).Subrouter()
	initRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/init", ah.Init)
	initRouter.Use(otelhttp.NewMiddleware("POST /application/version/init"))
	initRouter.Use(ah.MVInit)

	getIacCommandResultRouter := r.Methods(http.MethodGet).Subrouter()
	getIacCommandResultRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/result/{executionid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}", ah.GetIacCommandResult)
	getIacCommandResultRouter.Use(otelhttp.NewMiddleware("POST /application/version/result"))
	getIacCommandResultRouter.Use(ah.MVGetIacCommandResult)

	fmtRouter := r.Methods(http.MethodPost).Subrouter()
	fmtRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/fmt", ah.Fmt)
	fmtRouter.Use(otelhttp.NewMiddleware("POST /application/version/fmt"))
	fmtRouter.Use(ah.MVFmt)

	hclfmtRouter := r.Methods(http.MethodPost).Subrouter()
	hclfmtRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/hclfmt", ah.HclFmt)
	hclfmtRouter.Use(otelhttp.NewMiddleware("POST /application/version/hclfmt"))
	hclfmtRouter.Use(ah.MVHclFmt)

	forceUnlockRouter := r.Methods(http.MethodPost).Subrouter()
	forceUnlockRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/force-unlock", ah.ForceUnlock)
	forceUnlockRouter.Use(otelhttp.NewMiddleware("POST /application/version/force-unlock"))
	forceUnlockRouter.Use(ah.MVForceUnlock)

	providersRouter := r.Methods(http.MethodGet).Subrouter()
	providersRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/providers", ah.Providers)
	providersRouter.Use(otelhttp.NewMiddleware("POST /application/version/providers"))
	providersRouter.Use(ah.MVProviders)

	validateInputsRouter := r.Methods(http.MethodGet).Subrouter()
	validateInputsRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/validate-inputs", ah.ValidateInputs)
	validateInputsRouter.Use(otelhttp.NewMiddleware("POST /application/version/validate-inputs"))
	validateInputsRouter.Use(ah.MVValidateInputs)

	taintRouter := r.Methods(http.MethodPost).Subrouter()
	taintRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/taint", ah.Taint)
	taintRouter.Use(otelhttp.NewMiddleware("POST /application/version/taint"))
	taintRouter.Use(ah.MVTaint)

	untaintRouter := r.Methods(http.MethodPost).Subrouter()
	untaintRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/untaint", ah.Untaint)
	untaintRouter.Use(otelhttp.NewMiddleware("POST /application/version/untaint"))
	untaintRouter.Use(ah.MVUntaint)

	testRouter := r.Methods(http.MethodPost).Subrouter()
	testRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/test", ah.Test)
	testRouter.Use(otelhttp.NewMiddleware("POST /application/version/test"))
	testRouter.Use(ah.MVTest)

	renderJsonRouter := r.Methods(http.MethodPost).Subrouter()
	renderJsonRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/render-json", ah.RenderJson)
	renderJsonRouter.Use(otelhttp.NewMiddleware("POST /application/version/render-json"))
	renderJsonRouter.Use(ah.MVRenderJson)

	runAllRouter := r.Methods(http.MethodPost).Subrouter()
	runAllRouter.HandleFunc("/v1/applicationmgmt/application/{applicationid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}}/version/{versionnumber:[0-9]{1,4}}/run-all", ah.RunAll)
	runAllRouter.Use(otelhttp.NewMiddleware("POST /application/version/run-all"))
	runAllRouter.Use(ah.MVRunAll)

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
