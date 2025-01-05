package handlers

import (
	"DemoServer_ApplicationManager/helper"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

func (h ApplicationHandler) MVPackageUpload(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		// Limit the size of the request body
		r.Body = http.MaxBytesReader(rw, r.Body, int64(h.cfg.Storage.MaxPackageSize))

		// Check content type
		contentType := r.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "multipart/form-data") {
			helper.ReturnError(
				cl,
				http.StatusUnsupportedMediaType,
				helper.ErrorPackageInvalidContentType,
				fmt.Errorf("no internal error"),
				requestid,
				r,
				&rw,
				span)
			return
		}

		vars := mux.Vars(r)
		applicationid := vars["applicationid"]
		versionnumber := vars["versionnumber"]

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

		if len(versionnumber) == 0 {
			helper.ReturnError(
				cl,
				http.StatusBadRequest,
				helper.ErrorVersionNumberInvalid,
				fmt.Errorf("no internal error"),
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

func (h ApplicationHandler) MVGetPackageLink(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

		_, span, requestid, cl := h.setupTraceAndLogger(r, rw)
		defer span.End()

		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &rw, span)

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(rw, r)
	})
}
