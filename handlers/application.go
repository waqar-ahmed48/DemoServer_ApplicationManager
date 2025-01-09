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
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
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

	response, err := h.buildApplicationsResponse(applications, limit, skip)
	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

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

	var resp data.ApplicationResponseWrapper
	if err := utilities.CopyMatchingFields(application, &resp); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, resp, span)
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

	patch := r.Context().Value(KeyApplicationPatchParamsRecord{}).(*data.ApplicationPatchWrapper)
	applicationID := mux.Vars(r)["applicationid"]

	application, err := h.fetchApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, http.StatusNotFound, helper.ErrorResourceNotFound, err, requestid, r, &w, span)
		return
	}

	if err := h.updateApplication(application, *patch, ctx); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	var resp data.ApplicationResponseWrapper
	if err := utilities.CopyMatchingFields(application, &resp); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, &resp, span)
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

	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	application, err := h.fetchApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, http.StatusNotFound, helper.ErrorResourceNotFound, err, requestid, r, &w, span)
		return
	}

	if application.State != data.ApplicationState_Deactivated {
		helper.ReturnError(cl, http.StatusNotAcceptable, helper.ErrorApplicationUnexpectedState, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorApplicationUnexpectedState].Error()), requestid, r, &w, span)
		return
	}

	if err := h.deleteApplication(application, ctx); err != nil {
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
	if err := utilities.CopyMatchingFields(postWrapper, newApp); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

	if err := utilities.CreateObject(h.pd.RWDB(), &newApp, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	var resp data.ApplicationResponseWrapper
	if err := utilities.CopyMatchingFields(newApp, &resp); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, &resp, span)
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
	var err error
	result := h.pd.RODB().First(&application, "id = ?", applicationID)
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("application not found")
	}

	if application.Versions, err = h.fetchVersions(applicationID, h.list_limit, 0); err != nil {
		return nil, err
	}

	return &application, result.Error
}

func (h *ApplicationHandler) updateApplication(application *data.Application, patch data.ApplicationPatchWrapper, ctx context.Context) error {
	tx := h.pd.RWDB().Begin()
	if tx.Error != nil {
		return tx.Error
	}

	//ConnectionID is being patched. Have to link/unlink with ConnectionManager Microservice as well.
	if patch.ConnectionID != nil {
		if *patch.ConnectionID != "" {
			if application.ConnectionID != "" {
				pc, err := h.getGenericConnectionID(application.ConnectionID, ctx)
				if err != nil {
					tx.Rollback()
					return err
				}

				if err := h.unlinkAppFromConnection(application.ID.String(), pc, ctx); err != nil {
					tx.Rollback()
					return err
				}
			}

			pc, err := h.getGenericConnectionID(*patch.ConnectionID, ctx)
			if err != nil {
				tx.Rollback()
				return err
			}

			if err := h.linkAppToConnection(application.ID.String(), pc, ctx); err != nil {
				tx.Rollback()
				return err
			}
		} else {
			tx.Rollback()
			return helper.ErrorDictionary[helper.ErrorApplicationIDInvalid].Error()
		}
	}

	if err := utilities.CopyMatchingFields(patch, application); err != nil {
		tx.Rollback()
		return err
	}

	if err := utilities.UpdateObjectWithoutTx(tx, application, ctx, h.cfg.Server.PrefixMain); err != nil {
		tx.Rollback()
	}

	tx.Commit()

	return nil
}

func (h *ApplicationHandler) deleteApplication(application *data.Application, ctx context.Context) error {
	tx := h.pd.RWDB().Begin()
	if tx.Error != nil {
		return tx.Error
	}

	for _, version := range application.Versions {
		err := utilities.DeleteObjectWithoutTx(tx, &version, ctx, h.cfg.Server.PrefixMain)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	if err := utilities.DeleteObjectWithoutTx(tx, application, ctx, h.cfg.Server.PrefixMain); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete application: %w", err)
	}

	return tx.Commit().Error
}

func (h *ApplicationHandler) buildApplicationsResponse(applications []data.Application, limit, skip int) (*data.ApplicationsResponse, error) {
	response := data.ApplicationsResponse{
		Total:        len(applications),
		Limit:        limit,
		Skip:         skip,
		Applications: make([]data.ApplicationResponseWrapper, 0, len(applications)),
	}

	for _, app := range applications {
		var wrapped data.ApplicationResponseWrapper

		if err := utilities.CopyMatchingFields(app, &wrapped); err != nil {
			return nil, err
		}
		response.Applications = append(response.Applications, wrapped)
	}
	return &response, nil
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

	if err != nil {
		return nil, http.StatusInternalServerError, helper.ErrorApplicationIDInvalid, err
	} else {
		if application.ConnectionID == "" {
			return nil, http.StatusBadRequest, helper.ErrorConnectionMissing, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorConnectionMissing].Error())
		}

		if application.State != data.ApplicationState_Activated {
			return nil, http.StatusNotAcceptable, helper.ErrorApplicationUnexpectedState, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorApplicationUnexpectedState].Error())
		}
		return application, httpStatus, helperError, nil
	}
}

func (h *ApplicationHandler) generateAWSCreds(connectionid string, ctx context.Context) (*data.CredsAWSConnectionResponse, error) {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	resp, err := h.vh.GenerateCredsAWSSecretsEngine(h.cfg.Vault.PathPrefix+"/aws_"+connectionid, ctx)
	if err != nil {
		return nil, err
	}

	return resp, nil
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

func (h *ApplicationHandler) getGenericConnectionID(connectionid string, ctx context.Context) (string, error) {

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

	url := prefixHTTP + h.cfg.ConnectionManager.Host + ":" + strconv.Itoa(h.cfg.ConnectionManager.Port) + "/v1/connectionmgmt/connection/aws/" + connectionid
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)

	if err != nil {
		return "", err
	}

	if resp == nil {
		err = fmt.Errorf("response object is nil")
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("HTTP status code NOK. %d", resp.StatusCode)
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var r data.AWSConnectionResponseWrapper

	err = json.Unmarshal(body, &r)
	if err != nil {
		return "", err
	}

	return r.Connection.ID.String(), nil
}

func (h *ApplicationHandler) unlinkAppFromConnection(applicationid string, connectionid string, ctx context.Context) error {

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

	url := prefixHTTP + h.cfg.ConnectionManager.Host + ":" + strconv.Itoa(h.cfg.ConnectionManager.Port) + "/v1/connectionmgmt/connection/" + connectionid + "/unlink/" + applicationid
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
