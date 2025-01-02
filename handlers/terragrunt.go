package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

func (h *ApplicationHandler) Validate(w http.ResponseWriter, r *http.Request) {
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

	var httpStatus int
	var helperErr helper.ErrorTypeEnum
	var err error

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strExternalCommand := "terragrunt validate"
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				strExternalCommand)
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
			resp.Command = strExternalCommand
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

func (h *ApplicationHandler) Plan(w http.ResponseWriter, r *http.Request) {
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

	var httpStatus int
	var helperErr helper.ErrorTypeEnum
	var err error

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strExternalCommand := "terragrunt plan"
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				strExternalCommand)
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
			resp.Command = strExternalCommand
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

func (h *ApplicationHandler) Apply(w http.ResponseWriter, r *http.Request) {
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

	var httpStatus int
	var helperErr helper.ErrorTypeEnum
	var err error

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strExternalCommand := "terragrunt apply --auto-approve"
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				strExternalCommand)
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
			resp.Command = strExternalCommand
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

func (h *ApplicationHandler) Destroy(w http.ResponseWriter, r *http.Request) {
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

	var httpStatus int
	var helperErr helper.ErrorTypeEnum
	var err error

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strExternalCommand := "terragrunt destroy --auto-approve"
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				strExternalCommand)
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
			resp.Command = strExternalCommand
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

func (h *ApplicationHandler) Init(w http.ResponseWriter, r *http.Request) {
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

	var httpStatus int
	var helperErr helper.ErrorTypeEnum
	var err error

	_, httpStatus, helperErr, err = h.validateApplication(mux.Vars(r)["applicationid"])

	if err == nil {
		var version *data.Version
		version, httpStatus, helperErr, err = h.validateVersion(mux.Vars(r)["applicationid"], mux.Vars(r)["versionnumber"])

		if err == nil {
			strExternalCommand := "terragrunt init"
			strCommand := fmt.Sprintf(`docker run --rm -v %s:/workdir -w /workdir -e AWS_ACCESS_KEY_ID=%s -e AWS_SECRET_ACCESS_KEY=%s -e AWS_DEFAULT_REGION=us-west-2 my_terragrunt:latest "%s"`,
				version.PackagePath,
				h.cfg.AWS.ACCESS_KEY,
				h.cfg.AWS.SECRET_ACCESS_KEY,
				strExternalCommand)
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
			resp.Command = strExternalCommand
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
