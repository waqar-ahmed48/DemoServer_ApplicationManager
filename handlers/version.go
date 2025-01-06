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

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	var httpStatus int
	var helperErr helper.ErrorTypeEnum
	var err error
	var application *data.Application
	var version *data.Version
	var creds *data.CredsAWSConnectionResponse

	application, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])
	}

	if err == nil {
		creds, err = h.generateAWSCreds(application.ConnectionID, ctx)
	}

	if err == nil {
		//strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-east-2 my_terragrunt:latest "%s"`,
		var strCommand string

		if (action == data.Apply) || (action == data.Destroy) || (action == data.Plan) {
			strCommand = fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_SESSION_TOKEN=%s my_terragrunt:latest "%s"`,
				version.PackagePath,
				creds.Data.AccessKey,
				creds.Data.SecretKey,
				creds.Data.SessionToken,
				command)

		} else {
			strCommand = fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir my_terragrunt:latest "%s"`,
				version.PackagePath,
				command)
		}

		cmd := exec.Command("bash", "-c", strCommand)

		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		result := &data.AuditRecord{
			ID:              uuid.New(),
			ExecutionID:     uuid.New(),
			VersionID:       version.ID,
			ApplicationID:   version.ApplicationID,
			VersionNumber:   version.VersionNumber,
			ExecutionStatus: data.InProcess,
			StartTime:       time.Now(),
			Command:         command,
			//FullCommand:     "strCommand",
			Done:      make(chan bool, 1),
			Action:    action,
			RequestID: uuid.MustParse(requestid),
		}

		err := utilities.CreateObject(h.pd.RWDB(), &result, ctx, h.cfg.Server.PrefixMain)

		if err != nil {
			helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
		}

		// Run the command in a separate goroutine
		go func(result *data.AuditRecord, latency int, ctx context.Context) {
			defer close(result.Done)
			if latency > 0 {
				time.Sleep(10 * time.Second)
			}

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

			err = utilities.UpdateObject(h.pd.RWDB(), result, ctx, h.cfg.Server.PrefixMain)

			if err != nil {
				helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorDatastoreSaveFailed, err, requestid, r, &w, span)
			}
		}(result, creds.Latency, ctx)

		var resp data.AuditRecordWrapper

		_ = utilities.CopyMatchingFields(result, &resp)

		err = json.NewEncoder(w).Encode(&resp)

		if err != nil {
			helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
		}

		return
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
