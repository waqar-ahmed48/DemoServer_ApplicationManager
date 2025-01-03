package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"fmt"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel"
)

func (h *ApplicationHandler) Validate(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt validate"
	h.VersionExecIacCommand(w, r, command, data.Validate)
}

func (h *ApplicationHandler) Plan(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt plan"
	h.VersionExecIacCommand(w, r, command, data.Plan)
}

func (h *ApplicationHandler) Apply(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt apply --auto-approve"
	h.VersionExecIacCommand(w, r, command, data.Apply)
}

func (h *ApplicationHandler) Destroy(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt destroy --auto-approve"
	h.VersionExecIacCommand(w, r, command, data.Destroy)
}

func (h *ApplicationHandler) TGVersion(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) RunAll(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) RenderJson(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Test(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Untaint(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Taint(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) ValidateInputs(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Providers(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) ForceUnlock(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) HclFmt(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Fmt(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) GetIacCommandResult(w http.ResponseWriter, r *http.Request) {

	h.VersionIacCommandResult(w, r, r.Context())
}

func (h *ApplicationHandler) Init(w http.ResponseWriter, r *http.Request) {

	command := "terragrunt init"
	h.VersionExecIacCommand(w, r, command, data.Init)
}

func (h *ApplicationHandler) HclValidate(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Output(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) Refresh(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) CreateWorkspace(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) DeleteWorkspace(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)

}

func (h *ApplicationHandler) ShowWorkspace(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) SelectWorkspace(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) GetWorkspaces(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) ImportStateResource(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) RemoveStateResource(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) MoveStateResource(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}

func (h *ApplicationHandler) ListState(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnError(cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		fmt.Errorf("operation not implemented yet"),
		requestid,
		r,
		&w,
		span)
}
