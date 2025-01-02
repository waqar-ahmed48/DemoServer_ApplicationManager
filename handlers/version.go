package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
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

	helper.ReturnErrorWithAdditionalInfo(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		requestid,
		r,
		&w,
		err,
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

	helper.ReturnErrorWithAdditionalInfo(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		requestid,
		r,
		&w,
		err,
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

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]
	versionnumber := vars["versionnumber"]
	vn, _ := strconv.Atoi(versionnumber)

	var version data.Version

	result := h.pd.RODB().First(&version, "application_id = ? AND version_number = ?", applicationid, vn)

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

	var oRespConn data.VersionResponseWrapper
	_ = utilities.CopyMatchingFields(version, &oRespConn)

	err := json.NewEncoder(w).Encode(oRespConn)

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

	helper.LogError(cl, helper.ErrorNotImplemented, err, span)

	helper.ReturnErrorWithAdditionalInfo(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		requestid,
		r,
		&w,
		err,
		span)
}
