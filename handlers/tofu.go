package handlers

import (
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel"
)

func (h *ApplicationHandler) TofuVersion(w http.ResponseWriter, r *http.Request) {
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

func (h *ApplicationHandler) GraphTofu(w http.ResponseWriter, r *http.Request) {
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
