package utilities

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/mholt/archiver"
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
		srcField := srcVal.FieldByName(tgtField.Name)

		// Copy if srcField exists, is valid, and has the same type
		if srcField.IsValid() && srcField.Type() == tgtField.Type {
			tgtElem.Field(i).Set(srcField)
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
