package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/datalayer"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"bytes"
	"context"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/opentracing/opentracing-go"
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
	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	versionNumber := mux.Vars(r)["versionnumber"]

	_, httpStatus, helperErr, err := h.validateApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	version, httpStatus, helperErr, err := h.validateVersion(applicationID, versionNumber)
	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	// Prepare the command to execute
	strCommand := h.prepareDockerCommand(version.PackagePath, command)

	result := h.createAuditRecord(version, command, strCommand, action)
	if err := datalayer.CreateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	// Execute the command asynchronously
	go h.executeCommand(ctx, result, strCommand, requestid, r, cl, w, span)

	// Prepare response
	var resp data.AuditRecordWrapper
	if err := utilities.CopyMatchingFields(result, &resp); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONEncodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, resp, span)
}

func (h *ApplicationHandler) prepareDockerCommand(packagePath, command string) string {
	return fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
		packagePath,
		h.cfg.AWS.ACCESS_KEY,
		h.cfg.AWS.SECRET_ACCESS_KEY,
		command)
}

func (h *ApplicationHandler) createAuditRecord(version *data.Version, command, fullCommand string, action uuid.UUID) *data.AuditRecord {
	return &data.AuditRecord{
		ID:              uuid.New(),
		ExecutionID:     uuid.New(),
		VersionID:       version.ID,
		ApplicationID:   version.ApplicationID,
		VersionNumber:   version.VersionNumber,
		ExecutionStatus: data.InProcess,
		StartTime:       time.Now(),
		Command:         command,
		FullCommand:     fullCommand,
		Done:            make(chan bool, 1),
		Action:          action,
	}
}

func (h *ApplicationHandler) executeCommand(ctx context.Context, result *data.AuditRecord, strCommand, requestID string, r *http.Request, cl helper.Logger, w http.ResponseWriter, span opentracing.Span) {
	defer close(result.Done)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd := exec.Command("bash", "-c", strCommand)
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

	if err := datalayer.UpdateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestID, r, &w, span)
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

func (h *ApplicationHandler) VersionExecShellCommand(w http.ResponseWriter, r *http.Request, ctx context.Context, span trace.Span, externalCommand string, command string) {
	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	versionNumber := mux.Vars(r)["versionnumber"]

	_, httpStatus, helperErr, err := h.validateApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	version, httpStatus, helperErr, err := h.validateVersion(applicationID, versionNumber)
	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	// Prepare the command to execute
	strCommand := h.prepareDockerCommand(version.PackagePath, command)

	// Get the output of the command
	output, err := cmd.CombinedOutput()

	if err != nil {
		helper.LogDebug(cl, helper.ErrorPackageLSCommandError, err, span)
	}

	cleanedupOutput := utilities.StripEscapeSequences(string(output))

	result := h.createAuditRecord(version, command, strCommand, action, cleanedupOutput, err)
	if err := datalayer.CreateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, result, span)
}
