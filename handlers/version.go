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

func (h *ApplicationHandler) fetchVersions(applicationid string, limit int, skip int) ([]data.Version, error) {
	var versions []data.Version
	result := h.pd.RODB().Where("application_id = ?", applicationid).Limit(limit).Offset(skip).Order("version_number").Find(&versions)
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
	applicationid, _ := h.validateApplicationID(r, cl, w, span)

	versions, err := h.fetchVersions(applicationid, limit, skip)
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

	if err != nil {
		return nil, http.StatusInternalServerError, helper.ErrorApplicationIDInvalid, err
	} else {
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
		return version, httpStatus, helperError, nil
	}
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

func (h *ApplicationHandler) VersionExecIacCommandSync(applicationid string, versionNumber string, command string, action uuid.UUID, ctx context.Context) error {

	_, version, creds, err := h.prepareExecution(ctx, applicationid, versionNumber)
	if err != nil {
		return err
	}

	dockerCommand := h.buildDockerCommand(version.PackagePath, creds, command, action)

	if action == data.Apply {
		version.DemoStatus = data.Demo_Starting
	} else if action == data.Destroy {
		version.DemoStatus = data.Demo_Stopping
	}

	stdout, stderr, err := h.ExecuteCommandSync(version, dockerCommand, action, creds.Latency, ctx)
	var errorCode string
	var status data.ActionStatusTypeEnum
	if err != nil {
		errorCode = err.Error()
		status = data.Failed
	} else {
		status = data.Successful
	}

	result := utilities.InitializeAuditRecordSync(version, command, action, "", status, stdout, stderr, errorCode)

	if err := utilities.CreateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		return err
	}

	return nil
}

func (h *ApplicationHandler) VersionExecIacCommandAsync(w http.ResponseWriter, r *http.Request, command string, action uuid.UUID) error {
	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	versionNumber := mux.Vars(r)["versionnumber"]

	_, version, creds, err := h.prepareExecution(ctx, applicationID, versionNumber)
	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONDecodingFailed, err, requestid, r, &w, span)
		return err
	}

	dockerCommand := h.buildDockerCommand(version.PackagePath, creds, command, action)

	if action == data.Apply {
		version.DemoStatus = data.Demo_Starting
	} else if action == data.Destroy {
		version.DemoStatus = data.Demo_Stopping
	}

	result := utilities.InitializeAuditRecordAsync(version, command, action, requestid)

	if err := utilities.CreateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorFailedToCreateAuditRecord, err, requestid, r, &w, span)
		return err
	}

	go h.executeCommandAsync(version, dockerCommand, action, result, creds.Latency, ctx, cl, w, r, span, requestid)

	h.respondWithAuditRecord(w, cl, result, span)

	return nil
}

// prepareExecution validates and retrieves application, version, and AWS credentials.
func (h *ApplicationHandler) prepareExecution(ctx context.Context, applicationID string, versionNumber string) (*data.Application, *data.Version, *data.CredsAWSConnectionResponse, error) {
	application, _, _, err := h.validateApplication(applicationID)
	if err != nil {
		return nil, nil, nil, err
	}

	version, _, _, err := h.validateVersion(applicationID, versionNumber)
	if err != nil {
		return nil, nil, nil, err
	}

	creds, err := h.generateAWSCreds(application.ConnectionID, ctx)
	if err != nil {
		return nil, nil, nil, err
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

// executeCommandAsync runs the Docker command asynchronously and updates the audit record.
func (h *ApplicationHandler) executeCommandAsync(v *data.Version, command string, action uuid.UUID, result *data.AuditRecord, latency int, ctx context.Context, cl *slog.Logger, w http.ResponseWriter, r *http.Request, span trace.Span, requestID string) {
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

		if action == data.Apply {
			v.DemoStatus = data.Demo_FailedToStart
			v.DemoStartTime = time.Time{}
		} else if action == data.Destroy {
			v.DemoStatus = data.Demo_FailedToStop
		}

	} else {
		result.Status = data.Successful

		if action == data.Apply {
			v.DemoStatus = data.Demo_Running
			v.DemoStartTime = time.Now()
			v.DemoActualEndTime = time.Time{}
		} else if action == data.Destroy {
			v.DemoStatus = data.Demo_Stopped
			v.DemoActualEndTime = time.Now()
		}
	}

	result.ExecutionStatus = data.Completed
	result.EndTime = time.Now()

	if err := utilities.UpdateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.LogError(cl, helper.ErrorDatastoreSaveFailed, err, span)
	}
}

// executeCommandAsync runs the Docker command synchronously and updates the audit record.
func (h *ApplicationHandler) ExecuteCommandSync(v *data.Version, command string, action uuid.UUID, latency int, ctx context.Context) (string, string, error) {
	var stdout string
	var stderr string

	if latency > 0 {
		time.Sleep(time.Duration(latency) * time.Second)
	}

	cmd := exec.Command("bash", "-c", command)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	commandErr := cmd.Run()
	stdout = utilities.StripEscapeSequences(stdoutBuf.String())
	stderr = utilities.StripEscapeSequences(stderrBuf.String())

	return stdout, stderr, commandErr
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
