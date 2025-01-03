package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

var (
	iacCommandStore sync.Map // To store ongoing and completed commands
)

func (h *ApplicationHandler) UpdateVersion(w http.ResponseWriter, r *http.Request) {
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

	err := helper.ErrNotImplemented

	helper.LogError(cl, helper.ErrorNotImplemented, err, span)

	helper.ReturnError(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		err,
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) AddVersion(w http.ResponseWriter, r *http.Request) {
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

	err := helper.ErrNotImplemented

	helper.LogError(cl, helper.ErrorNotImplemented, err, span)

	helper.ReturnError(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		err,
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
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

	version, httpStatus, helperErr, err := h.getVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}

	var oRespConn data.VersionResponseWrapper
	_ = utilities.CopyMatchingFields(version, &oRespConn)

	err = json.NewEncoder(w).Encode(oRespConn)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h *ApplicationHandler) GetVersions(w http.ResponseWriter, r *http.Request) {
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

	vs := mux.Vars(r)
	applicationid := vs["applicationid"]

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

	var response data.VersionsResponse

	var versions []data.Version

	result := h.pd.RODB().
		Where("application_id = ?", applicationid).
		Limit(limit).
		Offset(skip).
		Order("id").
		Find(&versions) // Finds all application entries

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

	response.Total = len(versions)
	response.Skip = skip
	response.Limit = limit
	if response.Total == 0 {
		response.Versions = ([]data.VersionResponseWrapper{})
	} else {
		for _, value := range versions {
			var oRespConn data.VersionResponseWrapper
			_ = utilities.CopyMatchingFields(value, &oRespConn)
			response.Versions = append(response.Versions, oRespConn)
		}
	}

	err := json.NewEncoder(w).Encode(response)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}

}

func (h *ApplicationHandler) SetVersionState(w http.ResponseWriter, r *http.Request) {
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

	err := helper.ErrNotImplemented

	helper.ReturnError(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		err,
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) ArchiveVersion(w http.ResponseWriter, r *http.Request) {
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

	err := helper.ErrNotImplemented

	helper.ReturnError(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		err,
		requestid,
		r,
		&w,
		span)
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

func (h *ApplicationHandler) generateCommandID() string {
	return uuid.New().String()
}

func (h *ApplicationHandler) VersionExecIaCCommand(w http.ResponseWriter, r *http.Request, ctx context.Context, span trace.Span, command string) {
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

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				command)
			cmd := exec.Command("bash", "-c", strCommand)

			// Get the output of the command
			output, err := cmd.CombinedOutput()

			if err != nil {
				helper.LogDebug(cl, helper.ErrorPackageLSCommandError, err, span)
			}

			cleanedupOutput := utilities.StripEscapeSequences(string(output))

			var resp data.CommandOutputWrapper
			resp.ApplicationID = version.ApplicationID.String()
			resp.VersionID = version.ID
			resp.VersionNumber = version.VersionNumber
			resp.Command = command
			resp.Output = cleanedupOutput
			if err != nil {
				resp.Error = err.Error()
			}

			err = json.NewEncoder(w).Encode(resp)

			if err != nil {
				helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
			}

			return
		}
	}

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}
}

func (h *ApplicationHandler) VersionExecShellCommand(w http.ResponseWriter, r *http.Request, ctx context.Context, span trace.Span, externalCommand string, command string) {
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

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				command)
			cmd := exec.Command("bash", "-c", strCommand)

			// Get the output of the command
			output, err := cmd.CombinedOutput()

			if err != nil {
				helper.LogDebug(cl, helper.ErrorPackageLSCommandError, err, span)
			}

			cleanedupOutput := utilities.StripEscapeSequences(string(output))

			var resp data.CommandOutputWrapper
			resp.ApplicationID = version.ApplicationID.String()
			resp.VersionID = version.ID
			resp.VersionNumber = version.VersionNumber
			resp.Command = command
			resp.Output = cleanedupOutput
			if err != nil {
				resp.Error = err.Error()
			}

			err = json.NewEncoder(w).Encode(resp)

			if err != nil {
				helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
			}

			return
		}
	}

	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestid, r, &w, span)
		return
	}
}
