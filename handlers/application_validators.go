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
	"strconv"

	"github.com/go-playground/validator"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// Helper function to set up tracing and logging
func (h ApplicationHandler) setupTraceAndLogger(r *http.Request, rw http.ResponseWriter) (context.Context, trace.Span, string, *slog.Logger) {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)
	requestID, cl := helper.PrepareContext(r, &rw, traceLogger)

	return ctx, span, requestID, cl
}

// Generalized middleware for validating application IDs
func (h ApplicationHandler) validateApplicationID(r *http.Request, cl *slog.Logger, rw http.ResponseWriter, span trace.Span) (string, bool) {
	applicationID := mux.Vars(r)["applicationid"]
	if len(applicationID) == 0 {
		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorApplicationIDInvalid,
			fmt.Errorf("no internal error"),
			"",
			r,
			&rw,
			span,
		)
		return "", false
	}
	return applicationID, true
}

// Middleware for decoding and validating JSON payloads
func decodeAndValidate[T any](r *http.Request, cl *slog.Logger, rw http.ResponseWriter, span trace.Span) (*T, bool) {
	var payload T
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorInvalidJSONSchemaForParameter,
			err,
			"",
			r,
			&rw,
			span,
		)
		return nil, false
	}

	err = validator.New().Struct(payload)
	if err != nil {
		helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)
		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorInvalidJSONSchemaForParameter,
			err,
			"",
			r,
			&rw,
			span,
		)
		return nil, false
	}
	return &payload, true
}

// Middleware: MVApplication
func (h ApplicationHandler) MVApplication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, span, _, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		_, valid := h.validateApplicationID(r, cl, rw, span)
		if !valid {
			return
		}

		// Proceed to the next handler
		next.ServeHTTP(rw, r)
	})
}

// Middleware: MVAddApplication
func (h ApplicationHandler) MVAddApplication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ctx, span, _, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		payload, valid := decodeAndValidate[data.ApplicationPostWrapper](r, cl, rw, span)
		if !valid {
			return
		}

		// Add application to context
		ctx = context.WithValue(ctx, KeyApplicationRecord{}, payload)
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

// Middleware: MVApplicationUpdate
func (h ApplicationHandler) MVApplicationUpdate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ctx, span, _, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		_, valid := h.validateApplicationID(r, cl, rw, span)
		if !valid {
			return
		}

		payload, valid := decodeAndValidate[data.ApplicationPatchWrapper](r, cl, rw, span)
		if !valid {
			return
		}

		// Add application update to context
		ctx = context.WithValue(ctx, KeyApplicationPatchParamsRecord{}, payload)
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

// Middleware: MVQueryAudit and MVTGVersion (similar logic)
func (h ApplicationHandler) MVQueryAudit(next http.Handler) http.Handler {
	return h.genericApplicationHandler(next, KeyApplicationPatchParamsRecord{})
}

func (h ApplicationHandler) MVTGVersion(next http.Handler) http.Handler {
	return h.genericApplicationHandler(next, KeyApplicationPatchParamsRecord{})
}

// Generalized middleware for handlers requiring application ID and payload validation
func (h ApplicationHandler) genericApplicationHandler(next http.Handler, contextKey any) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ctx, span, _, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		_, valid := h.validateApplicationID(r, cl, rw, span)
		if !valid {
			return
		}

		payload, valid := decodeAndValidate[data.ApplicationPatchWrapper](r, cl, rw, span)
		if !valid {
			return
		}

		// Add validated data to context
		ctx = context.WithValue(ctx, contextKey, payload)
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

func (h ApplicationHandler) MVApplicationsGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		vars := r.URL.Query()

		// Validate limit parameter
		if err := validateQueryParam(vars.Get("limit"), 1, true, cl, r, rw, span, requestid, helper.ErrorInvalidValueForLimit); err != nil {
			return
		}

		// Validate skip parameter
		if err := validateQueryParam(vars.Get("skip"), 0, false, cl, r, rw, span, requestid, helper.ErrorInvalidValueForSkip); err != nil {
			return
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func validateQueryParam(
	param string,
	minValue int,
	strictGreaterThan bool,
	cl *slog.Logger,
	r *http.Request,
	rw http.ResponseWriter,
	span trace.Span,
	requestid string,
	helperError helper.ErrorTypeEnum) error {
	if param == "" {
		return nil
	}

	value, err := strconv.Atoi(param)
	if err != nil {
		helper.ReturnError(cl, http.StatusBadRequest, helperError, err, requestid, r, &rw, span)
		return err
	}

	if (strictGreaterThan && value <= minValue) || (!strictGreaterThan && value < minValue) {
		helper.ReturnError(cl, http.StatusBadRequest, helperError, fmt.Errorf("no internal error"), requestid, r, &rw, span)
		return fmt.Errorf("invalid value for parameter")
	}

	return nil
}
