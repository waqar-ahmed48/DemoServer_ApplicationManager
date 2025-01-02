package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-playground/validator"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

func (h ApplicationHandler) MVVersionsGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		_, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		v := mux.Vars(r)
		applicationid := v["applicationid"]

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		vars := r.URL.Query()

		limit_str := vars.Get("limit")
		if limit_str != "" {
			limit, err := strconv.Atoi(limit_str)
			if err != nil {
				helper.LogDebug(cl, helper.ErrorInvalidValueForLimit, err, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorInvalidValueForLimit,
					requestid,
					r,
					&rw,
					span)
				return
			}

			if limit <= 0 {
				helper.LogDebug(cl, helper.ErrorLimitMustBeGtZero, helper.ErrNone, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorLimitMustBeGtZero,
					requestid,
					r,
					&rw,
					span)
				return
			}
		}

		skip_str := vars.Get("skip")
		if skip_str != "" {
			skip, err := strconv.Atoi(skip_str)
			if err != nil {
				helper.LogDebug(cl, helper.ErrorInvalidValueForSkip, err, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorInvalidValueForSkip,
					requestid,
					r,
					&rw,
					span)
				return
			}

			if skip < 0 {
				helper.LogDebug(cl, helper.ErrorSkipMustBeGtZero, helper.ErrNone, span)

				helper.ReturnError(
					cl,
					http.StatusBadRequest,
					helper.ErrorSkipMustBeGtZero,
					requestid,
					r,
					&rw,
					span)
				return
			}
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		_, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]
		versionnumber := vars["versionnumber"]

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		if len(versionnumber) == 0 {
			helper.LogDebug(cl, helper.ErrorVersionNumberInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorVersionNumberInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersionPost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]
		var p data.ApplicationPatchWrapper

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		err = validator.New().Struct(p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		// add the application to the context
		ctx = context.WithValue(ctx, KeyApplicationPatchParamsRecord{}, p)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersionUpdate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]
		var p data.ApplicationPatchWrapper

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		err = validator.New().Struct(p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		// add the application to the context
		ctx = context.WithValue(ctx, KeyApplicationPatchParamsRecord{}, p)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersionArchive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		tr := otel.Tracer(h.cfg.Server.PrefixMain)
		ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
		defer span.End()

		// Add trace context to the logger
		traceLogger := h.l.With(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)

		requestid, cl := helper.PrepareContext(r, &rw, traceLogger)

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]
		var p data.ApplicationPatchWrapper

		if len(applicationid) == 0 {
			helper.LogDebug(cl, helper.ErrorApplicationIDInvalid, helper.ErrNone, span)

			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				requestid,
				r,
				&rw,
				span)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		err = validator.New().Struct(p)
		if err != nil {
			helper.LogDebug(cl, helper.ErrorInvalidJSONSchemaForParameter, err, span)

			helper.ReturnErrorWithAdditionalInfo(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				requestid,
				r,
				&rw,
				err,
				span)
			return

		}

		// add the application to the context
		ctx = context.WithValue(ctx, KeyApplicationPatchParamsRecord{}, p)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}
