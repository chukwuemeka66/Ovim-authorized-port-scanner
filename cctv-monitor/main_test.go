package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func unsetCameraEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"CAM_IP", "CAM_MJPEG_URL", "CAM_RTSP_URL", "WEB_ADDR"} {
		prev, existed := os.LookupEnv(k)
		_ = os.Unsetenv(k)
		if existed {
			t.Cleanup(func() {
				_ = os.Setenv(k, prev)
			})
		}
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	unsetCameraEnv(t)

	cfg := loadConfig()

	if cfg.IP != "127.0.0.1" {
		t.Fatalf("expected default IP 127.0.0.1, got %q", cfg.IP)
	}
	if cfg.MJPEGURL != "http://127.0.0.1:9080/mjpeg" {
		t.Fatalf("expected default MJPEGURL http://127.0.0.1:9080/mjpeg, got %q", cfg.MJPEGURL)
	}
	if cfg.RTSPURL != "rtsp://127.0.0.1:554/stream1" {
		t.Fatalf("expected default RTSPURL rtsp://127.0.0.1:554/stream1, got %q", cfg.RTSPURL)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("expected default Listen :8080, got %q", cfg.Listen)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("CAM_IP", "192.168.1.50")
	t.Setenv("CAM_MJPEG_URL", "http://192.168.1.50:9080/mjpeg")
	t.Setenv("CAM_RTSP_URL", "rtsp://192.168.1.50:554/stream1")
	t.Setenv("WEB_ADDR", ":9090")

	cfg := loadConfig()

	if cfg.IP != "192.168.1.50" {
		t.Fatalf("expected IP 192.168.1.50, got %q", cfg.IP)
	}
	if cfg.MJPEGURL != "http://192.168.1.50:9080/mjpeg" {
		t.Fatalf("unexpected MJPEGURL %q", cfg.MJPEGURL)
	}
	if cfg.RTSPURL != "rtsp://192.168.1.50:554/stream1" {
		t.Fatalf("unexpected RTSPURL %q", cfg.RTSPURL)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("expected Listen :9090, got %q", cfg.Listen)
	}
}

func TestLoadEnvFileMissingReturnsNil(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), ".env")
	if err := loadEnvFile(missingPath); err != nil {
		t.Fatalf("expected nil error for missing .env, got %v", err)
	}
}

func TestLoadEnvFileParsesAndRespectsExistingEnv(t *testing.T) {
	t.Setenv("CAM_IP", "10.0.0.5")

	envContent := "# Comment line\r\n" +
		"\r\n" +
		"CAM_IP=10.0.0.99\r\n" +
		"WEB_ADDR=\":8888\"\n" +
		"CAM_MJPEG_URL='http://10.0.0.99:9080/mjpeg'\n"

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte(envContent), 0o600); err != nil {
		t.Fatalf("failed to write temp .env: %v", err)
	}

	t.Setenv("WEB_ADDR", "")
	_ = os.Unsetenv("WEB_ADDR")
	t.Setenv("CAM_MJPEG_URL", "")
	_ = os.Unsetenv("CAM_MJPEG_URL")

	if err := loadEnvFile(envPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := os.Getenv("CAM_IP"); got != "10.0.0.5" {
		t.Fatalf("expected existing env CAM_IP=10.0.0.5 to win, got %q", got)
	}
	if got := os.Getenv("WEB_ADDR"); got != ":8888" {
		t.Fatalf("expected WEB_ADDR=:8888, got %q", got)
	}
	if got := os.Getenv("CAM_MJPEG_URL"); got != "http://10.0.0.99:9080/mjpeg" {
		t.Fatalf("expected CAM_MJPEG_URL=http://10.0.0.99:9080/mjpeg, got %q", got)
	}
}

func TestHandleSnapshotNoFrame(t *testing.T) {
	monitor := &Monitor{}
	req := httptest.NewRequest(http.MethodGet, "/snapshot.jpg", nil)
	recorder := httptest.NewRecorder()

	monitor.handleSnapshot(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("expected empty response body, got %d bytes", recorder.Body.Len())
	}
}

func TestHandleSnapshotReturnsCopyOfLatestFrame(t *testing.T) {
	monitor := &Monitor{}
	frame := []byte{0xff, 0xd8, 0x01, 0xff, 0xd9}
	monitor.latestJPEG = append([]byte(nil), frame...)

	req := httptest.NewRequest(http.MethodGet, "/snapshot.jpg", nil)
	recorder := httptest.NewRecorder()
	monitor.handleSnapshot(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "image/jpeg" {
		t.Fatalf("expected Content-Type image/jpeg, got %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}
	if !bytes.Equal(recorder.Body.Bytes(), frame) {
		t.Fatalf("unexpected snapshot body: %v", recorder.Body.Bytes())
	}
}
