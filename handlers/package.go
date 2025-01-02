package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

func (h *ApplicationHandler) GetPackageLink(w http.ResponseWriter, r *http.Request) {
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

	helper.ReturnErrorWithAdditionalInfo(
		cl,
		http.StatusInternalServerError,
		helper.ErrorNotImplemented,
		requestid,
		r,
		&w,
		err,
		span)
}

func (h *ApplicationHandler) UploadPackage(w http.ResponseWriter, r *http.Request) {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
	defer span.End()

	// Add trace context to the logger
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	requestid, cl := helper.PrepareContext(r, &w, traceLogger)

	helper.LogInfo(cl, helper.InfoHandlingRequest, helper.ErrNone, span)

	// Parse the multipart form
	err := r.ParseMultipartForm(int64(h.cfg.Storage.MaxPackageSize))
	if err != nil {
		helper.LogDebug(cl, helper.ErrorPackageFailedToParseMultipartForm, err, span)

		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorPackageFailedToParseMultipartForm,
			requestid,
			r,
			&w,
			span)
		return
	}

	// Retrieve the file
	file, handler, err := r.FormFile("file")
	if err != nil {
		helper.LogDebug(cl, helper.ErrorPackageFailedToParseMultipartForm, err, span)

		helper.ReturnError(
			cl,
			http.StatusBadRequest,
			helper.ErrorPackageFailedToParseMultipartForm,
			requestid,
			r,
			&w,
			span)
		return
	}
	defer file.Close()

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]
	versionnumber := vars["versionnumber"]
	vn, _ := strconv.Atoi(versionnumber)

	version, err := h.uploadPackage(applicationid, vn, file, handler, ctx)

	if err != nil {
		helper.LogError(cl, helper.ErrorPackageUploadFailed, err, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorPackageUploadFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	var oRespConn data.VersionResponseWrapper
	_ = utilities.CopyMatchingFields(version, &oRespConn)

	err = json.NewEncoder(w).Encode(oRespConn)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}

func (h *ApplicationHandler) uploadPackage(applicationid string, versionNumber int, file multipart.File, handler *multipart.FileHeader, ctx context.Context) (*data.Version, error) {

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	_, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	validExtensions := []string{".7z", ".tar", ".gz", ".zip"}
	fileExt := strings.ToLower(handler.Filename[strings.LastIndex(handler.Filename, "."):])
	isValidExt := false
	for _, ext := range validExtensions {
		if fileExt == ext {
			isValidExt = true
			break
		}
	}
	if !isValidExt {
		return nil, fmt.Errorf("unsupported file extension")
	}

	// Begin a transaction
	tx := h.pd.RWDB().Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return nil, tx.Error
	}

	var version data.Version

	var application data.Application

	result := tx.First(&application, "id = ?", applicationid)

	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		tx.Rollback()
		return nil, result.Error
	}

	result = tx.First(&version, "application_id = ? AND version_number = ?", applicationid, versionNumber)

	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		tx.Rollback()
		return nil, result.Error
	}

	// Save the file
	uploadFilePath := h.cfg.Storage.PackagesRootPath + "/" + application.OwnerID + "/" + applicationid + "/" + strconv.Itoa(versionNumber)

	err := utilities.TouchDirectory(uploadFilePath)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	uploadFilePath += "/" + handler.Filename
	uploadedFile, err := os.Create(uploadFilePath)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	defer uploadedFile.Close()

	_, err = io.Copy(uploadedFile, file)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	packageFilePath := h.cfg.Storage.PackagesRootPath + "/" + application.OwnerID + "/" + applicationid + "/" + strconv.Itoa(versionNumber) + "/"

	err = utilities.TouchDirectory(packageFilePath)

	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if fileExt == ".7z" {
		err = utilities.Decompress7z(uploadFilePath, packageFilePath)
	} else if fileExt == ".tar" {
		err = utilities.DecompressTar(uploadFilePath, packageFilePath)
	} else if fileExt == ".gz" {
		err = utilities.DecompressGzip(uploadFilePath, packageFilePath)
	} else if fileExt == ".zip" {
		err = utilities.DecompressZip(uploadFilePath, packageFilePath)
	} else {
		err = fmt.Errorf("unsupported file extension")
	}

	if err != nil {
		tx.Rollback()
		return nil, err
	}

	err = os.Remove(uploadFilePath)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	version.PackageUploaded = true
	version.PackagePath = packageFilePath
	version.PackageUploadedAt = time.Now()

	result = tx.Save(version)

	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &version, nil
}

func (h *ApplicationHandler) LSPackage(w http.ResponseWriter, r *http.Request) {
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

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]
	versionnumber := vars["versionnumber"]
	vn, _ := strconv.Atoi(versionnumber)

	var version data.Version

	result := h.pd.RODB().First(&version, "application_id = ? AND version_number = ?", applicationid, vn)

	if result.Error != nil {
		helper.LogError(cl, helper.ErrorDatastoreRetrievalFailed, result.Error, span)

		helper.ReturnError(
			cl,
			http.StatusInternalServerError,
			helper.ErrorDatastoreRetrievalFailed,
			requestid,
			r,
			&w,
			span)
		return
	}

	if result.RowsAffected == 0 {
		helper.LogDebug(cl, helper.ErrorResourceNotFound, helper.ErrNone, span)

		helper.ReturnError(
			cl,
			http.StatusNotFound,
			helper.ErrorResourceNotFound,
			requestid,
			r,
			&w,
			span)
		return
	}

	strCommand := `echo -e "Size\tDate\t\tTime\tName" && ls -laR --time-style=long-iso ` + version.PackagePath + `| awk '{print $5, $6, $7, $8}'`
	cmd := exec.Command("bash", "-c", strCommand)

	// Get the output of the command
	output, err := cmd.CombinedOutput()

	if err != nil {
		helper.LogDebug(cl, helper.ErrorPackageLSCommandError, err, span)
	}

	var resp data.CommandOutputWrapper
	resp.ApplicationID = version.ApplicationID.String()
	resp.VersionID = version.ID
	resp.VersionNumber = version.VersionNumber
	resp.Command = "ls -laR"
	resp.Output = string(output)
	if err != nil {
		resp.Error = err.Error()
	}

	err = json.NewEncoder(w).Encode(resp)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}
