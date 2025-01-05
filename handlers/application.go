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
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/trace"
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

	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	vars := r.URL.Query()
	limit := h.parseQueryParam(vars, "limit", h.list_limit, h.cfg.DataLayer.MaxResults)
	skip := h.parseQueryParam(vars, "skip", 0, math.MaxInt32)

	applications, err := h.fetchApplications(limit, skip)
	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreRetrievalFailed, err, requestid, r, &w, span)
		return
	}

	response := h.buildApplicationsResponse(applications, limit, skip)
	h.writeResponse(w, cl, response, span)
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

	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	application, err := h.fetchApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreRetrievalFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, application, span)
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

	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	patch := r.Context().Value(KeyApplicationPatchParamsRecord{}).(data.ApplicationPatchWrapper)
	applicationID := mux.Vars(r)["applicationid"]

	application, err := h.fetchApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, http.StatusNotFound, helper.ErrorResourceNotFound, err, requestid, r, &w, span)
		return
	}

	if err := h.updateApplication(application, patch, ctx); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, application, span)
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

	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	application, err := h.fetchApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, http.StatusNotFound, helper.ErrorResourceNotFound, err, requestid, r, &w, span)
		return
	}

	if err := h.deleteApplication(application); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreDeleteFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, data.DeleteApplicationResponse{
		StatusCode: http.StatusNoContent,
		Status:     http.StatusText(http.StatusNoContent),
	}, span)
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

	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	newApp := data.NewApplication(h.cfg)
	newApp.OwnerID = "e7a82149-907d-4ebf-8c12-d2748e0dc0d9"

	postWrapper := r.Context().Value(KeyApplicationRecord{}).(*data.ApplicationPostWrapper)
	utilities.CopyMatchingFields(postWrapper, newApp)

	if err := datalayer.CreateObject(h.pd.RWDB(), &newApp, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, newApp, span)
}

func (h *ApplicationHandler) parseQueryParam(vars url.Values, key string, defaultValue, maxValue int) int {
	valueStr := vars.Get(key)
	if valueStr != "" {
		value, err := strconv.Atoi(valueStr)
		if err == nil && value >= 0 {
			return int(math.Min(float64(value), float64(maxValue)))
		}
	}
	return defaultValue
}

func (h *ApplicationHandler) fetchApplications(limit, skip int) ([]data.Application, error) {
	var applications []data.Application
	result := h.pd.RODB().Limit(limit).Offset(skip).Order("name").Find(&applications)
	return applications, result.Error
}

func (h *ApplicationHandler) fetchApplication(applicationID string) (*data.Application, error) {
	var application data.Application
	result := h.pd.RODB().First(&application, "id = ?", applicationID)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("application not found")
	}
	return &application, result.Error
}

func (h *ApplicationHandler) updateApplication(application *data.Application, patch data.ApplicationPatchWrapper, ctx context.Context) error {
	utilities.CopyMatchingFields(patch, application)
	return datalayer.UpdateObject(h.pd.RWDB(), application, ctx, h.cfg.Server.PrefixMain)
}

func (h *ApplicationHandler) deleteApplication(application *data.Application) error {
	tx := h.pd.RWDB().Begin()
	if tx.Error != nil {
		return tx.Error
	}

	if err := tx.Exec("DELETE FROM applications WHERE id = ?", application.ID).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete application: %w", err)
	}

	return tx.Commit().Error
}

func (h *ApplicationHandler) buildApplicationsResponse(applications []data.Application, limit, skip int) data.ApplicationsResponse {
	response := data.ApplicationsResponse{
		Total:        len(applications),
		Limit:        limit,
		Skip:         skip,
		Applications: make([]data.ApplicationResponseWrapper, 0, len(applications)),
	}

	for _, app := range applications {
		var wrapped data.ApplicationResponseWrapper
		utilities.CopyMatchingFields(app, &wrapped)
		response.Applications = append(response.Applications, wrapped)
	}
	return response
}

func (h *ApplicationHandler) writeResponse(w http.ResponseWriter, cl *slog.Logger, data interface{}, span trace.Span) {
	if err := json.NewEncoder(w).Encode(data); err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h *ApplicationHandler) QueryAudit(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &w, span)
}

func (h *ApplicationHandler) validateApplication(applicationid string) (*data.Application, int, helper.ErrorTypeEnum, error) {
	application, httpStatus, helperError, err := h.getApplication(applicationid)

	if err == nil {
		if application.ConnectionID == "" {
			return nil, http.StatusBadRequest, helper.ErrorConnectionMissing, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorConnectionMissing].Error())
		}
	}

	return application, httpStatus, helperError, nil
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
