package handlers

import (
	"DemoServer_ApplicationManager/helper"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/trace"
)

func (h ApplicationHandler) MVVersionsGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		_, valid := h.validateApplicationID(r, cl, rw, span)
		if !valid {
			return
		}

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

// Generalized middleware for validating VersionNumber
func (h ApplicationHandler) validateVersionNumber(r *http.Request, cl *slog.Logger, rw http.ResponseWriter, span trace.Span) (string, bool) {
	versionNumber := mux.Vars(r)["versionnumber"]
	if len(versionNumber) == 0 {
		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorVersionNumberInvalid,
			fmt.Errorf("no internal error"),
			"",
			r,
			&rw,
			span,
		)
		return "", false
	}
	return versionNumber, true
}

func (h ApplicationHandler) MVVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, _, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		_, valid := h.validateApplicationID(r, cl, rw, span)
		if !valid {
			return
		}

		_, valid = h.validateVersionNumber(r, cl, rw, span)
		if !valid {
			return
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersionPost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, span, requestid, cl := h.setupTraceAndLogger(r, w)
		defer span.End()

		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &rw, span)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersionUpdate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &rw, span)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}

func (h ApplicationHandler) MVVersionArchive(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, w)
		defer span.End()

		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &rw, span)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}
