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
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

type KeyApplicationRecord struct{}
type KeyApplicationPatchParamsRecord struct{}

type ApplicationHandler struct {
	l                       *slog.Logger
	cfg                     *configuration.Config
	pd                      *datalayer.PostgresDataSource
	vh                      *secretsmanager.VaultHandler
	applications_list_limit int
}

func NewApplicationHandler(cfg *configuration.Config, l *slog.Logger, pd *datalayer.PostgresDataSource, vh *secretsmanager.VaultHandler) (*ApplicationHandler, error) {
	var a ApplicationHandler

	a.cfg = cfg
	a.l = l
	a.pd = pd
	a.applications_list_limit = cfg.Server.ListLimit
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

	limit, skip := h.applications_list_limit, 0

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
		helper.LogError(cl, helper.ErrorDatastoreRetrievalFailed, result.Error, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
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

func (h ApplicationHandler) MiddlewareValidateApplicationsGet(next http.Handler) http.Handler {
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
				helper.LogDebug(cl, helper.ErrorInvalidValueForLimit, err, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorInvalidValueForLimit,
					requestid,
					r,
					&rw,
					span)
				return
			}

			if limit <= 0 {
				helper.LogDebug(cl, helper.ErrorLimitMustBeGtZero, helper.ErrNone, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorLimitMustBeGtZero,
					requestid,
					r,
					&rw,
					span)
				return
			}
		}

		skip_str := vars.Get("skip")
		if skip_str != "" {
			skip, err := strconv.Atoi(skip_str)
			if err != nil {
				helper.LogDebug(cl, helper.ErrorInvalidValueForSkip, err, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorInvalidValueForSkip,
					requestid,
					r,
					&rw,
					span)
				return
			}

			if skip < 0 {
				helper.LogDebug(cl, helper.ErrorSkipMustBeGtZero, helper.ErrNone, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorSkipMustBeGtZero,
					requestid,
					r,
					&rw,
					span)
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

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]
	var application data.Application

	result := h.pd.RODB().First(&application, "id = ?", applicationid)

	if result.Error != nil {
		helper.LogError(cl, helper.ErrorDatastoreRetrievalFailed, result.Error, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	if result.RowsAffected == 0 {
		helper.LogDebug(cl, helper.ErrorResourceNotFound, helper.ErrNone, span)

		helper.ReturnError(
			cl,
			http.StatusNotFound,
			helper.ErrorResourceNotFound,
			requestid,
			r,
			&w,
			span)
		return
	}

	var oRespConn data.ApplicationResponseWrapper
	_ = utilities.CopyMatchingFields(application, &oRespConn)

	err := json.NewEncoder(w).Encode(oRespConn)

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

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]

	p := r.Context().Value(KeyApplicationPatchParamsRecord{}).(data.ApplicationPatchWrapper)

	var application data.Application

	result := h.pd.RODB().First(&application, "id = ?", applicationid)

	if result.Error != nil {
		helper.LogError(cl, helper.ErrorDatastoreRetrievalFailed, result.Error, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	if result.RowsAffected == 0 {
		helper.LogDebug(cl, helper.ErrorResourceNotFound, helper.ErrNone, span)

		helper.ReturnError(
			cl,
			http.StatusNotFound,
			helper.ErrorResourceNotFound,
			requestid,
			r,
			&w,
			span)
		return
	}

	_ = utilities.CopyMatchingFields(p, &application)

	err := h.updateApplication(&application, ctx)

	if err != nil {
		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, err, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreSaveFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	result = h.pd.RODB().First(&application, "id = ?", applicationid)

	if result.Error != nil {
		helper.LogError(cl, helper.ErrorDatastoreRetrievalFailed, result.Error, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	if result.RowsAffected == 0 {
		helper.LogDebug(cl, helper.ErrorResourceNotFound, helper.ErrNone, span)

		helper.ReturnError(
			cl,
			http.StatusNotFound,
			helper.ErrorResourceNotFound,
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

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]

	var application data.Application
	var err error

	application.ID, err = uuid.Parse(applicationid)

	if err != nil {
		helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, err, span)

		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorApplicationIDInvalid,
			requestid,
			r,
			&w,
			span)
		return
	}

	result := h.pd.RODB().First(&application, "id = ?", applicationid)

	if result.Error != nil {
		helper.LogError(cl, helper.ErrorDatastoreRetrievalFailed, result.Error, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	if result.RowsAffected == 0 {
		helper.LogDebug(cl, helper.ErrorResourceNotFound, helper.ErrNone, span)

		helper.ReturnError(
			cl,
			http.StatusNotFound,
			helper.ErrorResourceNotFound,
			requestid,
			r,
			&w,
			span)
		return
	}

	err = h.deleteApplication(&application, ctx)

	if err != nil {
		helper.LogDebug(cl, helper.ErrorDatastoreDeleteFailed, err, span)

		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorDatastoreDeleteFailed,
			requestid,
			r,
			&w,
			span)
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
	ctx, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
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

func (h *ApplicationHandler) updateApplication(a *data.Application, ctx context.Context) error {

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
	}

	result := tx.Save(a)

	if result.Error != nil {
		tx.Rollback()
		return result.Error
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

	a := r.Context().Value(KeyApplicationRecord{}).(*data.Application)

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, tx.Error, span)

		helper.ReturnErrorWithAdditionalInfo(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreSaveFailed,
			requestid,
			r,
			&w,
			tx.Error,
			span)
		return
	}

	result := tx.Create(&a)

	if result.Error != nil {
		tx.Rollback()

		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, result.Error, span)

		helper.ReturnErrorWithAdditionalInfo(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreSaveFailed,
			requestid,
			r,
			&w,
			result.Error,
			span)
		return
	}

	if result.RowsAffected != 1 {
		tx.Rollback()

		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, helper.ErrNone, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreSaveFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	err := tx.Commit().Error

	if err != nil {
		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, err, span)

		helper.ReturnErrorWithAdditionalInfo(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreSaveFailed,
			requestid,
			r,
			&w,
			tx.Error,
			span)
		return
	}

	var c_wrapper data.ApplicationResponseWrapper

	_ = utilities.CopyMatchingFields(a, &c_wrapper)

	err = json.NewEncoder(w).Encode(c_wrapper)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}

	a = nil
}

func (h ApplicationHandler) MiddlewareValidateApplication(next http.Handler) http.Handler {
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

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MiddlewareValidateApplicationPost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		a := data.NewApplication(h.cfg)

		err := a.FromJSON(r.Body)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		err = a.Validate()
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		// add the application to the context
		ctx = context.WithValue(ctx, KeyApplicationRecord{}, a)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MiddlewareValidateApplicationUpdate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]
		var p data.ApplicationPatchWrapper

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		err = validator.New().Struct(p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		// add the application to the context
		ctx = context.WithValue(ctx, KeyApplicationPatchParamsRecord{}, p)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}
