package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/trace"
)

func (h *ApplicationHandler) UpdateVersion(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &w, span)
}

func (h *ApplicationHandler) AddVersion(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &w, span)
}

func (h *ApplicationHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	version, httpStatus, helperErr, err := h.getVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	var oRespConn data.VersionResponseWrapper
	if err := utilities.CopyMatchingFields(version, &oRespConn); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONEncodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, oRespConn, span)
}

func (h *ApplicationHandler) fetchVersions(limit, skip int) ([]data.Version, error) {
	var versions []data.Version
	result := h.pd.RODB().Limit(limit).Offset(skip).Order("name").Find(&versions)
	return versions, result.Error
}

func (h *ApplicationHandler) buildVersionsResponse(versions []data.Version, limit, skip int) (*data.VersionsResponse, error) {
	response := data.VersionsResponse{
		Total:    len(versions),
		Limit:    limit,
		Skip:     skip,
		Versions: make([]data.VersionResponseWrapper, 0, len(versions)),
	}

	for _, app := range versions {
		var wrapped data.VersionResponseWrapper

		if err := utilities.CopyMatchingFields(app, &wrapped); err != nil {
			return nil, err
		}
		response.Versions = append(response.Versions, wrapped)
	}
	return &response, nil
}

func (h *ApplicationHandler) GetVersions(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	vars := r.URL.Query()
	limit := h.parseQueryParam(vars, "limit", h.list_limit, h.cfg.DataLayer.MaxResults)
	skip := h.parseQueryParam(vars, "skip", 0, math.MaxInt32)

	versions, err := h.fetchVersions(limit, skip)
	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreRetrievalFailed, err, requestid, r, &w, span)
		return
	}

	response, err := h.buildVersionsResponse(versions, limit, skip)
	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, response, span)

}

func (h *ApplicationHandler) SetVersionState(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &w, span)
}

func (h *ApplicationHandler) ArchiveVersion(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &w, span)
}

func (h *ApplicationHandler) validateVersion(applicationid string, versionNumber string) (*data.Version, int, helper.ErrorTypeEnum, error) {
	version, httpStatus, helperError, err := h.getVersion(applicationid, versionNumber)

	if err == nil {
		if !version.PackageUploaded {
			return nil, http.StatusBadRequest, helper.ErrorPackageNotUploaded, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorPackageNotUploaded].Error())
		} else {
			if version.PackagePath == "" {
				return nil, http.StatusInternalServerError, helper.ErrorPackageInvalidState, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorPackageInvalidState].Error())
			} else {
				_, err = os.Stat(version.PackagePath)

				if err != nil {
					return nil, http.StatusInternalServerError, helper.ErrorPackageInvalidState, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorPackageInvalidState].Error())
				}
			}

		}
	}

	return version, httpStatus, helperError, nil
}

func (h *ApplicationHandler) getVersion(applicationid string, versionNumber string) (*data.Version, int, helper.ErrorTypeEnum, error) {
	vn, _ := strconv.Atoi(versionNumber)

	var version data.Version

	result := h.pd.RODB().First(&version, "application_id = ? AND version_number = ?", applicationid, vn)

	if result.Error != nil {
		return nil, http.StatusInternalServerError, helper.ErrorDatastoreRetrievalFailed, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, http.StatusNotFound, helper.ErrorResourceNotFound, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorResourceNotFound].Error())
	}

	return &version, http.StatusOK, helper.ErrorNone, nil
}

func (h *ApplicationHandler) getCommandOutput(applicationid string, versionNumber string, executionid string) (*data.AuditRecord, int, helper.ErrorTypeEnum, error) {
	vn, _ := strconv.Atoi(versionNumber)

	var a data.AuditRecord

	result := h.pd.RODB().First(&a, "application_id = ? AND version_number = ? AND execution_id = ?", applicationid, vn, executionid)

	if result.Error != nil {
		return nil, http.StatusInternalServerError, helper.ErrorDatastoreRetrievalFailed, result.Error
	}

	if result.RowsAffected == 0 {
		return nil, http.StatusNotFound, helper.ErrorResourceNotFound, fmt.Errorf("%s", helper.ErrorDictionary[helper.ErrorResourceNotFound].Error())
	}

	return &a, http.StatusOK, helper.ErrorNone, nil
}

func (h *ApplicationHandler) VersionExecIacCommand(w http.ResponseWriter, r *http.Request, command string, action uuid.UUID) {
	ctx, span, requestID, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	versionNumber := mux.Vars(r)["versionnumber"]

	application, version, creds, err := h.prepareExecution(ctx, cl, applicationID, versionNumber, requestID)
	if err != nil {
		handleExecutionError(w, r, cl, err, span, requestID)
		return
	}

	dockerCommand := h.buildDockerCommand(version.PackagePath, creds, command, action)
	result := h.initializeAuditRecord(version, command, action, requestID)

	if err := utilities.CreateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		handleExecutionError(w, r, cl, fmt.Errorf("failed to create audit record: %w", err), span, requestID)
		return
	}

	go h.executeCommandAsync(dockerCommand, result, creds.Latency, ctx, cl, w, r, span, requestID)

	h.respondWithAuditRecord(w, cl, result, span)
}

// prepareExecution validates and retrieves application, version, and AWS credentials.
func (h *ApplicationHandler) prepareExecution(ctx context.Context, cl helper.Logger, applicationID, versionNumber, requestID string) (*data.Application, *data.Version, *data.CredsAWSConnectionResponse, error) {
	application, httpStatus, helperErr, err := h.validateApplication(applicationID)
	if err != nil {
		return nil, nil, nil, wrapError(httpStatus, helperErr, err)
	}

	version, httpStatus, helperErr, err := h.validateVersion(applicationID, versionNumber)
	if err != nil {
		return nil, nil, nil, wrapError(httpStatus, helperErr, err)
	}

	creds, err := h.generateAWSCreds(application.ConnectionID, ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate AWS credentials: %w", err)
	}

	return application, version, creds, nil
}

// buildDockerCommand constructs the appropriate Docker command string.
func (h *ApplicationHandler) buildDockerCommand(packagePath string, creds *data.CredsAWSConnectionResponse, command string, action uuid.UUID) string {
	if action == data.Apply || action == data.Destroy || action == data.Plan {
		return fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_SESSION_TOKEN=%s my_terragrunt:latest "%s"`,
			packagePath, creds.Data.AccessKey, creds.Data.SecretKey, creds.Data.SessionToken, command)
	}
	return fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir my_terragrunt:latest "%s"`,
		packagePath, command)
}

// initializeAuditRecord sets up a new audit record.
func (h *ApplicationHandler) initializeAuditRecord(version *data.Version, command string, action uuid.UUID, requestID string) *data.AuditRecord {
	return &data.AuditRecord{
		ID:              uuid.New(),
		ExecutionID:     uuid.New(),
		VersionID:       version.ID,
		ApplicationID:   version.ApplicationID,
		VersionNumber:   version.VersionNumber,
		ExecutionStatus: data.InProcess,
		StartTime:       time.Now(),
		Command:         command,
		Action:          action,
		RequestID:       uuid.MustParse(requestID),
		Done:            make(chan bool, 1),
	}
}

// executeCommandAsync runs the Docker command asynchronously and updates the audit record.
func (h *ApplicationHandler) executeCommandAsync(command string, result *data.AuditRecord, latency int, ctx context.Context, cl *slog.Logger, w http.ResponseWriter, r *http.Request, span trace.Span, requestID string) {
	defer close(result.Done)

	if latency > 0 {
		time.Sleep(time.Duration(latency) * time.Second)
	}

	cmd := exec.Command("bash", "-c", command)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	result.Output = utilities.StripEscapeSequences(stdoutBuf.String())
	result.Error = utilities.StripEscapeSequences(stderrBuf.String())
	if err != nil {
		result.ErrorCode = err.Error()
		result.Status = data.Failed
	} else {
		result.Status = data.Successful
	}
	result.ExecutionStatus = data.Completed
	result.EndTime = time.Now()

	if err := utilities.UpdateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, err, span)
	}
}

// respondWithAuditRecord sends the audit record as a JSON response.
func (h *ApplicationHandler) respondWithAuditRecord(w http.ResponseWriter, cl *slog.Logger, result *data.AuditRecord, span trace.Span) {
	var resp data.AuditRecordWrapper
	if err := utilities.CopyMatchingFields(result, &resp); err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
		return
	}

	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

// handleExecutionError centralizes error handling for the function.
func handleExecutionError(w http.ResponseWriter, r *http.Request, cl *slog.Logger, err error, span trace.Span, requestID string) {
	if wrappedErr, ok := err.(wrappedError); ok {
		helper.ReturnError(cl, wrappedErr.httpStatus, wrappedErr.helperErr, wrappedErr.err, requestID, r, &w, span)
	} else {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorInternalServer, err, requestID, r, &w, span)
	}
}

// wrapError creates a wrapped error with HTTP status and helper error type.
type wrappedError struct {
	httpStatus int
	helperErr  helper.ErrorTypeEnum
	err        error
}

func wrapError(httpStatus int, helperErr helper.ErrorTypeEnum, err error) error {
	return wrappedError{httpStatus: httpStatus, helperErr: helperErr, err: err}
}

func (h *ApplicationHandler) VersionIacCommandResult(w http.ResponseWriter, r *http.Request, ctx context.Context) {
	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	versionNumber := mux.Vars(r)["versionnumber"]
	executionID := mux.Vars(r)["executionid"]

	ar, httpStatus, helperErr, err := h.getCommandOutput(applicationID, versionNumber, executionID)

	if err == nil {
		var resp data.AuditRecordWrapper

		if err := utilities.CopyMatchingFields(ar, &resp); err != nil {
			helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONEncodingFailed, err, requestid, r, &w, span)
			return
		}

		h.writeResponse(w, cl, resp, span)
		return
	}

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}
}
