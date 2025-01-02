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

	"github.com/go-playground/validator"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

func (h ApplicationHandler) MVGraphTofu(next http.Handler) http.Handler {
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
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				fmt.Errorf("no internal error"),
				requestid,
				r,
				&rw,
				span)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				err,
				requestid,
				r,
				&rw,
				span)
			return

		}

		err = validator.New().Struct(p)
		if err != nil {
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				err,
				requestid,
				r,
				&rw,
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

func (h ApplicationHandler) MVTofuVersion(next http.Handler) http.Handler {
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
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorApplicationIDInvalid,
				fmt.Errorf("no internal error"),
				requestid,
				r,
				&rw,
				span)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				err,
				requestid,
				r,
				&rw,
				span)
			return

		}

		err = validator.New().Struct(p)
		if err != nil {
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorInvalidJSONSchemaForParameter,
				err,
				requestid,
				r,
				&rw,
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
