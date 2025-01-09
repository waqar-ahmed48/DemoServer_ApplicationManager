package utilities

import (
	"DemoServer_ApplicationManager/data"
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"github.com/mholt/archiver"
	"go.opentelemetry.io/otel"
	"gorm.io/gorm"
)

type MultiThreadedFunc func(threadId int, opsPerThread int)

func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(funcName, "/")

	return parts[len(parts)-1]
}

func CallMultiThreadedFunc(f MultiThreadedFunc, count int, threads int) {
	var wg sync.WaitGroup
	wg.Add(threads)

	// Use a channel to signal completion of each thread
	done := make(chan struct{})

	// Divide the work among multiple threads
	opsPerThread := count / threads
	for i := 0; i < threads; i++ {
		go func(threadID int) {
			defer wg.Done()
			f(threadID, opsPerThread)
			done <- struct{}{}
		}(i)
	}

	// Wait for all threads to complete
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for the completion signal
	<-done
}

// initializeAuditRecord sets up a new audit record for Async command execution
func InitializeAuditRecordAsync(version *data.Version, command string, action data.ActionTypeEnum, requestID string) *data.AuditRecord {
	return &data.AuditRecord{
		ID:              uuid.New(),
		ExecutionID:     uuid.New(),
		VersionID:       version.ID,
		ApplicationID:   version.ApplicationID,
		VersionNumber:   version.VersionNumber,
		ExecutionStatus: data.InProcess,
		StartTime:       time.Now(),
		Command:         command,
		Action:          action,
		RequestID:       uuid.MustParse(requestID),
		Done:            make(chan bool, 1),
	}
}

// initializeAuditRecordSync sets up a new audit record for synchronous command execution
func InitializeAuditRecordSync(version *data.Version, command string, action data.ActionTypeEnum, requestID string, status data.ActionStatusTypeEnum, os string, es string, ec string) *data.AuditRecord {
	return &data.AuditRecord{
		ID:              uuid.New(),
		VersionID:       version.ID,
		ApplicationID:   version.ApplicationID,
		VersionNumber:   version.VersionNumber,
		ExecutionStatus: data.Completed,
		StartTime:       time.Now(),
		EndTime:         time.Now(),
		Command:         command,
		Action:          action,
		Output:          os,
		Error:           es,
		ErrorCode:       ec,
		RequestID:       uuid.MustParse(requestID),
		Status:          status,
	}
}

func CopyMatchingFields(src, tgt interface{}) error {
	srcVal := reflect.ValueOf(src)
	tgtVal := reflect.ValueOf(tgt)

	// Ensure tgt is a pointer and can be dereferenced
	if tgtVal.Kind() != reflect.Ptr || tgtVal.IsNil() {
		return errors.New("target object must be a non-nil pointer to a struct")
	}

	tgtElem := tgtVal.Elem() // Dereference the pointer

	// Ensure tgtElem is a struct
	if tgtElem.Kind() != reflect.Struct {
		return errors.New("target object must be a pointer to a struct")
	}

	// Ensure src is a struct or a pointer to a struct
	if srcVal.Kind() == reflect.Ptr {
		srcVal = srcVal.Elem() // Dereference if it's a pointer
	}

	if srcVal.Kind() != reflect.Struct {
		return errors.New("source object must be a struct or a pointer to a struct")
	}

	// Iterate through the fields of the target struct
	for i := 0; i < tgtElem.NumField(); i++ {
		tgtField := tgtElem.Type().Field(i)
		tgtFieldVal := tgtElem.Field(i)
		srcField := srcVal.FieldByName(tgtField.Name)

		// Ensure srcField exists and is valid
		if !srcField.IsValid() || !tgtFieldVal.CanSet() {
			continue
		}

		srcFieldType := srcField.Type()
		srcFieldName := tgtField.Name

		// Skip if the field is a struct or pointer to a struct
		if srcFieldType.Kind() == reflect.Struct ||
			(srcFieldType.Kind() == reflect.Ptr && srcFieldType.Elem().Kind() == reflect.Struct) {
			// Updated CopyMatchingFields logic
			if srcField.Type().Kind() == reflect.Ptr && !srcField.IsNil() {
				// Source field is a non-nil pointer
				if tgtFieldVal.Kind() == reflect.Ptr {
					// Both source and destination fields are pointers
					if tgtFieldVal.Type() == srcField.Type() {
						// Types match, copy directly
						tgtFieldVal.Set(srcField)
					} else if tgtFieldVal.Type().Elem() == srcField.Type().Elem() {
						// Underlying types match, create a new value and copy
						newVal := reflect.New(tgtFieldVal.Type().Elem())
						newVal.Elem().Set(srcField.Elem())
						tgtFieldVal.Set(newVal)
					} else {
						// Log type mismatch
						fmt.Printf("Skipping field %s: incompatible pointer types (source: %s, target: %s)\n",
							srcFieldName, srcField.Type(), tgtFieldVal.Type())
					}
				} else {
					// Destination is not a pointer, check for direct assignment compatibility
					if tgtFieldVal.Type() == srcField.Type().Elem() {
						tgtFieldVal.Set(srcField.Elem())
					} else {
						// Log type mismatch
						fmt.Printf("Skipping field %s: incompatible types (source: %s, target: %s)\n",
							srcFieldName, srcField.Type().Elem(), tgtFieldVal.Type())
						continue
					}
				}
			} else {
				// Source is not a pointer, handle direct assignment
				if tgtFieldVal.Kind() == reflect.Ptr {
					// Destination is a pointer, create a new value
					if tgtFieldVal.Type().Elem() == srcField.Type() {
						newVal := reflect.New(tgtFieldVal.Type().Elem())
						newVal.Elem().Set(srcField)
						tgtFieldVal.Set(newVal)
					} else {
						// Log type mismatch
						fmt.Printf("Skipping field %s: incompatible types (source: %s, target: %s)\n",
							srcFieldName, srcField.Type(), tgtFieldVal.Type())
						continue
					}
				} else {
					// Direct assignment
					if tgtFieldVal.Type() == srcField.Type() {
						tgtFieldVal.Set(srcField)
					} else {
						// Log type mismatch
						fmt.Printf("Skipping field %s: incompatible types (source: %s, target: %s)\n",
							srcFieldName, srcField.Type(), tgtFieldVal.Type())
						continue
					}
				}
			}

		}

		// Handle pointer-to-value or pointer-to-pointer cases
		if srcField.Kind() == reflect.Ptr {
			if !srcField.IsNil() {
				// Dereference pointer from src and set if tgt is non-pointer
				if tgtFieldVal.Kind() != reflect.Ptr {
					tgtFieldVal.Set(srcField.Elem())
				} else {
					// Both src and tgt are pointers
					tgtFieldVal.Set(srcField)
				}
			}
		} else {
			// Both src and tgt are non-pointers
			if tgtFieldVal.Kind() == srcField.Kind() {
				tgtFieldVal.Set(srcField)
			}
		}
	}

	return nil
}

// DecompressZip decompresses a .zip file
func DecompressZip(zipPath, destDir string) error {
	zipFile, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("unable to open zip file: %v", err)
	}
	defer zipFile.Close()

	for _, file := range zipFile.File {
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to open zip file %v: %v", file.Name, err)
		}
		defer rc.Close()

		destPath := fmt.Sprintf("%s/%s", destDir, file.Name)
		destFile, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("unable to create file %v: %v", destPath, err)
		}
		defer destFile.Close()

		_, err = io.Copy(destFile, rc)
		if err != nil {
			return fmt.Errorf("unable to copy content to file %v: %v", destPath, err)
		}
	}
	return nil
}

// DecompressGzip decompresses a .gz file
func DecompressGzip(gzipPath, destPath string) error {
	file, err := os.Open(gzipPath)
	if err != nil {
		return fmt.Errorf("unable to open gzip file: %v", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("unable to create gzip reader: %v", err)
	}
	defer gzipReader.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("unable to create destination file: %v", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, gzipReader)
	if err != nil {
		return fmt.Errorf("unable to copy content to file: %v", err)
	}

	return nil
}

// DecompressTar decompresses a .tar file
func DecompressTar(tarPath, destDir string) error {
	file, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("unable to open tar file: %v", err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("unable to read tar file: %v", err)
		}

		destPath := fmt.Sprintf("%s/%s", destDir, header.Name)
		destFile, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("unable to create file %v: %v", destPath, err)
		}
		defer destFile.Close()

		_, err = io.Copy(destFile, tarReader)
		if err != nil {
			return fmt.Errorf("unable to copy content to file %v: %v", destPath, err)
		}
	}
	return nil
}

// Decompress7z decompresses a .7z file using archiver
func Decompress7z(sevenZPath, destDir string) error {
	// Extract the .7z file
	err := archiver.Archive([]string{sevenZPath}, destDir)
	if err != nil {
		return fmt.Errorf("unable to decompress .7z file: %v", err)
	}
	return nil
}

func MoveFile(sourcePath, destPath string) error {
	// First, copy the file
	err := CopyFile(sourcePath, destPath)
	if err != nil {
		return err
	}

	// After copying, remove the original file
	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to remove original file: %v", err)
	}

	return nil
}

func CopyFile(sourcePath, destPath string) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %v", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	return nil
}

func TouchDirectory(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path, 0700)

			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

func StripEscapeSequences(s string) string {
	// Regular expression to match ANSI escape codes
	re := regexp.MustCompile(`\x1b\[[0-9;]*[mK]`)

	// Replace all ANSI escape sequences with an empty string
	cleanOutput := re.ReplaceAllString(s, "")

	return cleanOutput
}

func UpdateObject[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := db.Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
	}

	result := tx.Save(obj)

	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func UpdateObjectWithoutTx[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	result := db.Save(obj)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func DeleteObject[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := db.Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
	}

	result := tx.Delete(obj)

	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func DeleteObjectWithoutTx[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	result := db.Delete(obj)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected != 1 {
		return fmt.Errorf("unexpected affected row count. Expected: 1, Actual: %d", result.RowsAffected)
	}

	return nil
}

func CreateObject[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := db.Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
	}

	result := tx.Create(obj)

	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func CreateObjectWithoutTx[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	result := db.Create(obj)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func CreateObjectTx[T any](db *gorm.DB, obj *T, ctx context.Context, tracerName string) error {

	tr := otel.Tracer(tracerName)
	_, span := tr.Start(ctx, GetFunctionName())
	defer span.End()

	// Begin a transaction
	tx := db.Begin()

	// Check if the transaction started successfully
	if tx.Error != nil {
		return tx.Error
	}

	result := tx.Create(obj)

	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func ValidateAndWrapPayload(payload map[string]interface{}, target interface{}) error {
	// Ensure target is a pointer
	targetVal := reflect.ValueOf(target)
	if targetVal.Kind() != reflect.Ptr || targetVal.IsNil() {
		return errors.New("target must be a non-nil pointer to a struct")
	}

	// Ensure target is a struct
	targetElem := targetVal.Elem()
	if targetElem.Kind() != reflect.Struct {
		return errors.New("target must point to a struct")
	}

	// Marshal the map into JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.New("failed to marshal payload into JSON: " + err.Error())
	}

	// Unmarshal JSON into the target struct
	err = json.Unmarshal(payloadBytes, target)
	if err != nil {
		return errors.New("failed to unmarshal JSON into target struct: " + err.Error())
	}

	// Validate the target struct
	validate := validator.New()

	// Custom tag registration for skipping fields
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	err = validate.Struct(target)
	if err != nil {
		return errors.New("validation failed: " + err.Error())
	}

	return nil
}
