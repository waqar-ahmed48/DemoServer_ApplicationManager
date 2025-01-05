package handlers

import (
	"DemoServer_ApplicationManager/configuration"
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/datalayer"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/secretsmanager"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
)

type KeyApplicationRecord struct{}
type KeyApplicationPatchParamsRecord struct{}

type ApplicationHandler struct {
	l          *slog.Logger
	cfg        *configuration.Config
	pd         *datalayer.PostgresDataSource
	vh         *secretsmanager.VaultHandler
	list_limit int
}

func NewApplicationHandler(cfg *configuration.Config, l *slog.Logger, pd *datalayer.PostgresDataSource, vh *secretsmanager.VaultHandler) (*ApplicationHandler, error) {
	var a ApplicationHandler

	a.cfg = cfg
	a.l = l
	a.pd = pd
	a.list_limit = cfg.Server.ListLimit
	a.vh = vh

	return &a, nil
}

func (h *ApplicationHandler) GetApplications(w http.ResponseWriter, r *http.Request) {

	// swagger:operation GET /applications - GetApplications
	// List Applications
	//
	// Endpoint: GET - /v1/applicationmgmt/applications
	//
	// Description: Returns list of Appliction resources.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	// - name: limit
	//   in: query
	//   description: maximum number of results to return.
	//   required: false
	//   type: integer
	//   format: int32
	// - name: skip
	//   in: query
	//   description: number of results to be skipped from beginning of list
	//   required: false
	//   type: integer
	//   format: int32
	// responses:
	//   '200':
	//     description: List of Application resources
	//     schema:
	//       type: array
	//       items:
	//         "$ref": "#/definitions/Application"
	//   '400':
	//     description: Issues with parameters or their value
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   '500':
	//     description: Internal server error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   default:
	//     description: unexpected error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	_, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	vars := r.URL.Query()

	limit, skip := h.list_limit, 0

	limit_str := vars.Get("limit")
	if limit_str != "" {
		limit, _ = strconv.Atoi(limit_str)
	}

	skip_str := vars.Get("skip")
	if skip_str != "" {
		skip, _ = strconv.Atoi(skip_str)
	}

	if limit == -1 || limit > h.cfg.DataLayer.MaxResults {
		limit = h.cfg.DataLayer.MaxResults
	}

	var response data.ApplicationsResponse

	var applications []data.Application

	result := h.pd.RODB().
		Limit(limit).
		Offset(skip).
		Order("name").      // Orders by the name in the application table
		Find(&applications) // Finds all application entries

	if result.Error != nil {
		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
			result.Error,
			requestid,
			r,
			&w,
			span)
		return
	}

	response.Total = len(applications)
	response.Skip = skip
	response.Limit = limit
	if response.Total == 0 {
		response.Applications = ([]data.ApplicationResponseWrapper{})
	} else {
		for _, value := range applications {
			var oRespConn data.ApplicationResponseWrapper
			_ = utilities.CopyMatchingFields(value, &oRespConn)
			response.Applications = append(response.Applications, oRespConn)
		}
	}

	err := json.NewEncoder(w).Encode(response)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h ApplicationHandler) MVApplicationsGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		_, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		vars := r.URL.Query()

		limit_str := vars.Get("limit")
		if limit_str != "" {
			limit, err := strconv.Atoi(limit_str)
			if err != nil {
				helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorInvalidValueForLimit, err, requestid, r, &rw, span)
				return
			}

			if limit <= 0 {
				helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorLimitMustBeGtZero, fmt.Errorf("no internal error"), requestid, r, &rw, span)
				return
			}
		}

		skip_str := vars.Get("skip")
		if skip_str != "" {
			skip, err := strconv.Atoi(skip_str)
			if err != nil {
				helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorInvalidValueForSkip, err, requestid, r, &rw, span)
				return
			}

			if skip < 0 {
				helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorSkipMustBeGtZero, fmt.Errorf("no internal error"), requestid, r, &rw, span)
				return
			}
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

// GetApplication returns Application resource based on applicationid parameter
func (h *ApplicationHandler) GetApplication(w http.ResponseWriter, r *http.Request) {

	// swagger:operation GET /applicationn Application GetApplication
	// Retrieve Application
	//
	// Endpoint: GET - /v1/applicationmgmt/application/{applicationid}
	//
	// Description: Returns Application resource based on applicationid.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	// - name: applicationid
	//   in: query
	//   description: id for Application resource to be retrieved. expected to be in uuid format i.e. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	//   required: true
	//   type: string
	// responses:
	//   '200':
	//     description: Application resource
	//     schema:
	//         "$ref": "#/definitions/Application"
	//   '404':
	//     description: Resource not found.
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   '500':
	//     description: Internal server error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   default:
	//     description: unexpected error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	_, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	application, httpStatus, helperErr, err := h.getApplication(mux.Vars(r)["applicationid"])

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	var oRespConn data.ApplicationResponseWrapper
	_ = utilities.CopyMatchingFields(application, &oRespConn)

	err = json.NewEncoder(w).Encode(oRespConn)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h *ApplicationHandler) UpdateApplication(w http.ResponseWriter, r *http.Request) {

	// swagger:operation PATCH /application Application UpdateApplication
	// Update Application
	//
	// Endpoint: PATCH - /v1/applicationmgmt/application/{applicationid}
	//
	// Description: Update attributes of Application resource.
	//
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: applicationid
	//   in: query
	//   description: id for Application resource to be retrieved. expected to be in uuid format i.e. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	//   required: true
	//   type: string
	// - in: body
	//   name: Body
	//   description: JSON string defining Application resource.
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/ApplicationPatchWrapper"
	// responses:
	//   '200':
	//     description: Application resource after updates.
	//     schema:
	//         "$ref": "#/definitions/Application"
	//   '400':
	//     description: Bad request or parameters
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   default:
	//     description: unexpected error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	p := r.Context().Value(KeyApplicationPatchParamsRecord{}).(data.ApplicationPatchWrapper)
	//var payload map[string]interface{}
	//payload = r.Context().Value(KeyApplicationPatchParamsRecord{}).(map[string]interface{})

	applicationid := mux.Vars(r)["applicationid"]

	application, httpStatus, helperErr, err := h.getApplication(applicationid)

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
	}

	err = utilities.CopyMatchingFields(p, application)

	if err != nil {
		tx.Rollback()
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

	err = utilities.UpdateObjectWithoutTx(tx, application, ctx, h.cfg.Server.PrefixMain)

	if err != nil {
		tx.Rollback()
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	if p.ConnectionID != nil {
		if application.ConnectionID != *p.ConnectionID {
			if application.ConnectionID != "" {
				err := h.unlinkAppFromConnection(application, ctx)

				if err != nil {
					tx.Rollback()
					helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorApplicationFailedToUnlinkFromConnection, err, requestid, r, &w, span)
					return
				}
			}

			err := h.linkAppToConnection(applicationid, *p.ConnectionID, ctx)

			if err != nil {
				tx.Rollback()
				helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorApplicationFailedToLinkConnection, err, requestid, r, &w, span)
				return
			}
		}
	}

	err = tx.Commit().Error

	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	application, httpStatus, helperErr, err = h.getApplication(applicationid)

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	var oRespConn data.ApplicationResponseWrapper
	_ = utilities.CopyMatchingFields(application, &oRespConn)

	err = json.NewEncoder(w).Encode(oRespConn)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

// DeleteApplication deletes the Application from datastore
func (h *ApplicationHandler) DeleteApplication(w http.ResponseWriter, r *http.Request) {

	// swagger:operation DELETE /application Application DeleteApplication
	// Delete Application
	//
	// Endpoint: DELETE - /v1/applicationmgmt/application/{applicationid}
	//
	// Description: Returns Application resource based on applicationid.
	//
	// ---
	// produces:
	// - application/json
	// parameters:
	// - name: applicationid
	//   in: query
	//   description: id for Application resource to be retrieved. expected to be in uuid format i.e. XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	//   required: true
	//   type: string
	// responses:
	//   '200':
	//     description: Resource successfully deleted.
	//     schema:
	//         "$ref": "#/definitions/DeleteApplicationResponse"
	//   '404':
	//     description: Resource not found.
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   '500':
	//     description: Internal server error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   default:
	//     description: unexpected error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	applicationid := mux.Vars(r)["applicationid"]

	application, httpStatus, helperErr, err := h.getApplication(applicationid)

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	if application.State != data.ApplicationState_Deactivated {
		helper.ReturnError(cl, http.StatusNotAcceptable, helper.ErrorApplicationUnexpectedState, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorApplicationUnexpectedState].Error()), requestid, r, &w, span)
		return
	}

	err = h.deleteApplication(application, ctx)

	if err != nil {
		helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorDatastoreDeleteFailed, err, requestid, r, &w, span)
		return
	}

	var response data.DeleteApplicationResponse
	response.StatusCode = http.StatusNoContent
	response.Status = http.StatusText(response.StatusCode)

	err = json.NewEncoder(w).Encode(response)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h *ApplicationHandler) deleteApplication(a *data.Application, ctx context.Context) error {

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	_, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
	}

	// Unlink from connection
	err := h.unlinkAppFromConnection(a, ctx)

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to unlink connection: %w", err)
	}

	// Delete from applications
	if err := tx.Exec("DELETE FROM audit_records WHERE application_id = ?", a.ID).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to purge audit_records: %w", err)
	}

	// Delete from applications
	if err := tx.Exec("DELETE FROM versions WHERE application_id = ?", a.ID).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to purge versions: %w", err)
	}

	// Delete from applications
	if err := tx.Exec("DELETE FROM applications WHERE id = ?", a.ID).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete application: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (h *ApplicationHandler) AddApplication(w http.ResponseWriter, r *http.Request) {

	// swagger:operation POST /application Application AddApplication
	// New Application
	//
	// Endpoint: POST - /v1/applicationmgmt/application
	//
	// Description: Create new Application resource.
	//
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - in: body
	//   name: Body
	//   description: JSON string defining Application resource
	//   required: true
	//   schema:
	//     "$ref": "#/definitions/ApplicationPostWrapper"
	// responses:
	//   '200':
	//     description: Application resource created.
	//     schema:
	//         "$ref": "#/definitions/Application"
	//   '500':
	//     description: Internal server error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"
	//   default:
	//     description: unexpected error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	p := r.Context().Value(KeyApplicationRecord{}).(*data.ApplicationPostWrapper)

	a := data.NewApplication(h.cfg)
	_ = a.NewVersion()

	utilities.CopyMatchingFields(p, a)

	//set dummy ownerid for now.
	a.OwnerID = "e7a82149-907d-4ebf-8c12-d2748e0dc0d9"

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, tx.Error, requestid, r, &w, span)
		return
	}

	err := utilities.CreateObject(h.pd.RWDB(), &a, r.Context(), h.cfg.Server.PrefixMain)

	if err != nil {
		tx.Rollback()
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, tx.Error, requestid, r, &w, span)
		return
	}

	if a.ConnectionID != "" {
		err := h.linkAppToConnection(a.ID.String(), a.ConnectionID, ctx)

		if err != nil {
			tx.Rollback()
			helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorApplicationFailedToLinkConnection, err, requestid, r, &w, span)
			return
		}
	}

	err = tx.Commit().Error

	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, tx.Error, requestid, r, &w, span)
		return
	}

	applicationid := a.ID
	application, httpStatus, helperErr, err := h.getApplication(applicationid.String())

	if err != nil {
		helper.ReturnError(cl,
			httpStatus,
			helperErr,
			err,
			requestid,
			r,
			&w,
			span)
		return
	}

	var oRespConn data.ApplicationResponseWrapper
	_ = utilities.CopyMatchingFields(application, &oRespConn)

	err = json.NewEncoder(w).Encode(oRespConn)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h *ApplicationHandler) QueryAudit(w http.ResponseWriter, r *http.Request) {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	_, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) validateApplication(applicationid string) (*data.Application, int, helper.ErrorTypeEnum, error) {
	application, httpStatus, helperError, err := h.getApplication(applicationid)

	if err == nil {
		if application.ConnectionID == "" {
			return nil, http.StatusBadRequest, helper.ErrorConnectionMissing, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorConnectionMissing].Error())
		}

		if application.State != data.ApplicationState_Activated {
			return nil, http.StatusNotAcceptable, helper.ErrorApplicationUnexpectedState, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorApplicationUnexpectedState].Error())
		}
	}

	return application, httpStatus, helperError, nil
}

func (h *ApplicationHandler) generateAWSCreds(connectionid string, ctx context.Context) (*data.CredsAWSConnectionResponse, error) {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	var prefixHTTP string

	c := http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   time.Duration(h.cfg.ConnectionManager.Timeout) * time.Second,
	}

	if h.cfg.ConnectionManager.HTTPS {
		prefixHTTP = "https://"
	} else {
		prefixHTTP = "http://"
	}

	url := prefixHTTP + h.cfg.ConnectionManager.Host + ":" + strconv.Itoa(h.cfg.ConnectionManager.Port) + "/v1/connectionmgmt/connection/aws/" + connectionid + "/creds"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)

	if err != nil {
		return nil, err
	}

	if resp == nil {
		err = fmt.Errorf("response object is nil")
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP status code NOK. %d", resp.StatusCode)
		return nil, err
	}

	b, _ := io.ReadAll(resp.Body)

	var rc data.CredsAWSConnectionResponse

	err = json.Unmarshal(b, &rc)
	if err != nil {
		return nil, err
	}

	if rc.Data.AccessKey == "" || rc.Data.SecretKey == "" {
		err = fmt.Errorf("creds not generated")
		return nil, err
	}

	return &rc, nil
}

func (h *ApplicationHandler) getApplication(applicationid string) (*data.Application, int, helper.ErrorTypeEnum, error) {
	var application data.Application

	result := h.pd.RODB().First(&application, "id = ?", applicationid)

	if result.Error != nil {
		return nil, http.StatusInternalServerError, helper.ErrorDatastoreRetrievalFailed, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, http.StatusNotFound, helper.ErrorResourceNotFound, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorResourceNotFound].Error())
	}

	return &application, http.StatusOK, helper.ErrorNone, nil
}

func (h *ApplicationHandler) linkAppToConnection(applicationid string, connectionid string, ctx context.Context) error {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	var prefixHTTP string

	c := http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   time.Duration(h.cfg.ConnectionManager.Timeout) * time.Second,
	}

	if h.cfg.ConnectionManager.HTTPS {
		prefixHTTP = "https://"
	} else {
		prefixHTTP = "http://"
	}

	url := prefixHTTP + h.cfg.ConnectionManager.Host + ":" + strconv.Itoa(h.cfg.ConnectionManager.Port) + "/v1/connectionmgmt/connection/" + connectionid + "/link/" + applicationid
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)

	if err != nil {
		return err
	}

	if resp == nil {
		err = fmt.Errorf("response object is nil")
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP status code NOK. %d", resp.StatusCode)
		return err
	}

	return nil
}

func (h *ApplicationHandler) unlinkAppFromConnection(application *data.Application, ctx context.Context) error {

	if application.ConnectionID == "" {
		return nil
	}

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	var prefixHTTP string

	c := http.Client{
		Transport: otelhttp.NewTransport(http.DefaultTransport),
		Timeout:   time.Duration(h.cfg.ConnectionManager.Timeout) * time.Second,
	}

	if h.cfg.ConnectionManager.HTTPS {
		prefixHTTP = "https://"
	} else {
		prefixHTTP = "http://"
	}

	url := prefixHTTP + h.cfg.ConnectionManager.Host + ":" + strconv.Itoa(h.cfg.ConnectionManager.Port) + "/v1/connectionmgmt/connection/" + application.ConnectionID + "/unlink/" + application.ID.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)

	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)

	if err != nil {
		return err
	}

	if resp == nil {
		err = fmt.Errorf("response object is nil")
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP status code NOK. %d", resp.StatusCode)
		return err
	}

	return nil
}
