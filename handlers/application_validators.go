package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-playground/validator"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

func (h ApplicationHandler) MVApplication(next http.Handler) http.Handler {
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

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVAddApplication(next http.Handler) http.Handler {
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

		var p data.ApplicationPostWrapper

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
		ctx = context.WithValue(ctx, KeyApplicationRecord{}, &p)
		r = r.WithContext(ctx)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVApplicationUpdate(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVQueryAudit(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVListState(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVMoveStateResource(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVRemoveStateResource(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVImportStateResource(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVGetWorkspaces(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVSelectWorkspace(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVShowWorkspace(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVDeleteWorkspace(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVCreateWorkspace(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVOutput(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVRefresh(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVTGVersion(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVDestroy(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVApply(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVPlan(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVValidate(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVHclValidate(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVInit(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVFmt(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVForceUnlock(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVProviders(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVHclFmt(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVValidateInputs(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVTaint(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVUntaint(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVTest(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVRenderJson(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVRunAll(next http.Handler) http.Handler {
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

func (h ApplicationHandler) MVSetVersionState(next http.Handler) http.Handler {
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
