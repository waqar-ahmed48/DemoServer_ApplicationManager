package handlers

import (
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"gorm.io/gorm"
)

func (h *ApplicationHandler) GetPackageLink(w http.ResponseWriter, r *http.Request) {
	_, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorNotImplemented, fmt.Errorf("operation not implemented yet"), requestid, r, &w, span)
}

func (h *ApplicationHandler) UploadPackage(w http.ResponseWriter, r *http.Request) {
	ctx, span, requestid, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	// Parse the multipart form
	err := r.ParseMultipartForm(int64(h.cfg.Storage.MaxPackageSize))
	if err != nil {
		helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorPackageFailedToParseMultipartForm, err, requestid, r, &w, span)
		return
	}

	// Retrieve the file
	file, handler, err := r.FormFile("file")
	if err != nil {
		helper.ReturnError(cl, http.StatusBadRequest, helper.ErrorPackageFailedToParseMultipartForm, err, requestid, r, &w, span)
		return
	}
	defer file.Close()

	vars := mux.Vars(r)
	applicationid := vars["applicationid"]
	versionnumber := vars["versionnumber"]
	vn, _ := strconv.Atoi(versionnumber)

	version, err := h.uploadPackage(applicationid, vn, file, handler, ctx)

	if err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorPackageUploadFailed, err, requestid, r, &w, span)
		return
	}

	var oRespConn data.VersionResponseWrapper
	if err := utilities.CopyMatchingFields(version, &oRespConn); err != nil {
		helper.ReturnError(cl, http.StatusInternalServerError, helper.ErrorJSONEncodingFailed, err, requestid, r, &w, span)
		return
	}

	h.writeResponse(w, cl, oRespConn, span)
}

func (h *ApplicationHandler) uploadPackage(applicationid string, versionNumber int, file multipart.File, handler *multipart.FileHeader, ctx context.Context) (*data.Version, error) {

	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	_, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	// Validate file extension
	if err := h.validateFileExtension(handler.Filename); err != nil {
		return nil, err
	}

	// Start transaction
	tx := h.pd.RWDB().Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Validate application and version
	application, version, err := h.validateApplicationAndVersion(tx, applicationID, versionNumber)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// Save and decompress file
	uploadFilePath, packageFilePath, err := h.saveAndDecompressFile(file, handler.Filename, application, applicationID, versionNumber)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// Update version information
	version.PackageUploaded = true
	version.PackagePath = packageFilePath
	version.PackageUploadedAt = time.Now()

	if err := tx.Save(&version).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &version, nil
}

func (h *ApplicationHandler) executeListCommand(path string, externalCommand string) (string, error) {
	command := `echo -e "Size\tDate\t\tTime\tName" && ` + externalCommand + ` ` + path + ` | awk '{print $5, $6, $7, $8}'`
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()

	return utilities.StripEscapeSequences(string(output)), err
}

func (h *ApplicationHandler) validateFileExtension(filename string) error {
	validExtensions := []string{".7z", ".tar", ".gz", ".zip"}
	fileExt := strings.ToLower(filepath.Ext(filename))

	for _, ext := range validExtensions {
		if fileExt == ext {
			return nil
		}
	}

	return fmt.Errorf("unsupported file extension: %s", fileExt)
}

func (h *ApplicationHandler) validateApplicationAndVersion(tx *gorm.DB, applicationID string, versionNumber int) (*data.Application, *data.Version, error) {
	var application data.Application
	var version data.Version

	if err := tx.First(&application, "id = ?", applicationID).Error; err != nil {
		return nil, nil, err
	}

	if err := tx.First(&version, "application_id = ? AND version_number = ?", applicationID, versionNumber).Error; err != nil {
		return nil, nil, err
	}

	return &application, &version, nil
}

func (h *ApplicationHandler) saveAndDecompressFile(file multipart.File, filename string, application *data.Application, applicationID string, versionNumber int) (string, string, error) {
	basePath := filepath.Join(h.cfg.Storage.PackagesRootPath, application.OwnerID, applicationID, strconv.Itoa(versionNumber))
	uploadFilePath := filepath.Join(basePath, filename)

	if err := utilities.TouchDirectory(basePath); err != nil {
		return "", "", err
	}

	uploadedFile, err := os.Create(uploadFilePath)
	if err != nil {
		return "", "", err
	}
	defer uploadedFile.Close()

	if _, err := io.Copy(uploadedFile, file); err != nil {
		return "", "", err
	}

	// Decompress the file
	if err := h.decompressFile(uploadFilePath, basePath); err != nil {
		return "", "", err
	}

	// Remove uploaded archive
	if err := os.Remove(uploadFilePath); err != nil {
		return "", "", err
	}

	return uploadFilePath, basePath, nil
}

func (h *ApplicationHandler) decompressFile(uploadFilePath, destinationPath string) error {
	switch filepath.Ext(uploadFilePath) {
	case ".7z":
		return utilities.Decompress7z(uploadFilePath, destinationPath)
	case ".tar":
		return utilities.DecompressTar(uploadFilePath, destinationPath)
	case ".gz":
		return utilities.DecompressGzip(uploadFilePath, destinationPath)
	case ".zip":
		return utilities.DecompressZip(uploadFilePath, destinationPath)
	default:
		return fmt.Errorf("unsupported file extension")
	}
}

func (h *ApplicationHandler) LSPackage(w http.ResponseWriter, r *http.Request) {
	_, span, requestID, cl := h.setupTraceAndLogger(r, w)
	defer span.End()

	applicationID := mux.Vars(r)["applicationid"]
	versionNumber := mux.Vars(r)["versionnumber"]

	_, httpStatus, helperErr, err := h.validateApplication(applicationID)
	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestID, r, &w, span)
		return
	}

	version, httpStatus, helperErr, err := h.validateVersion(applicationID, versionNumber)
	if err != nil {
		helper.ReturnError(cl, httpStatus, helperErr, err, requestID, r, &w, span)
		return
	}

	externalCommand := "ls -laR --time-style=long-iso"
	output, err := h.executeListCommand(externalCommand, version.PackagePath)
	response := data.AuditRecordWrapper{
		ApplicationID: version.ApplicationID,
		VersionID:     version.ID,
		VersionNumber: version.VersionNumber,
		Command:       externalCommand,
		Output:        output,
	}

	if err != nil {
		response.Error = err.Error()
	}

	h.writeResponse(w, cl, response, span)
}
