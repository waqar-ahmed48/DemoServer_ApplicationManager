package handlers

import (
	"DemoServer_ApplicationManager/helper"
	"fmt"
	"net/http"
)

func (h ApplicationHandler) MVPackageUpload(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		// Limit the size of the request body
		r.Body = http.MaxBytesReader(rw, r.Body, int64(h.cfg.Storage.MaxPackageSize))

		valid := h.validateContentTypeHeader(r, cl, rw, requestid, span)

		if !valid {
			return
		}

		_, valid = h.validateApplicationID(r, cl, rw, span)
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

func (h ApplicationHandler) MVGetPackageLink(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &rw, span)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}
