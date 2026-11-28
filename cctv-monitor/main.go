package main

import (
	"bytes"
	"context"
	"fmt"
	"image/jpeg"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type CameraConfig struct {
	IP       string
	MJPEGURL string
	RTSPURL  string
	Listen   string
}

type Monitor struct {
	cfg           CameraConfig
	mu            sync.RWMutex
	latestJPEG    []byte
	prevGray      []uint8
	width, height int
	lastAlert     time.Time
	alertCount    int
	lastAlertFile string
}

func loadConfig() CameraConfig {
	ip := os.Getenv("CAM_IP")
	if ip == "" {
		ip = "127.0.0.1"
	}
	mjpeg := os.Getenv("CAM_MJPEG_URL")
	if mjpeg == "" {
		mjpeg = fmt.Sprintf("http://%s:9080/mjpeg", ip)
	}
	rtsp := os.Getenv("CAM_RTSP_URL")
	if rtsp == "" {
		rtsp = fmt.Sprintf("rtsp://%s:554/stream1", ip)
	}
	listen := os.Getenv("WEB_ADDR")
	if listen == "" {
		listen = ":8080"
	}
	return CameraConfig{
		IP:       ip,
		MJPEGURL: mjpeg,
		RTSPURL:  rtsp,
		Listen:   listen,
	}
}

func loadEnvFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			continue
		}

		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}

		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Monitor) processFrame(jpegBytes []byte) {
	img, err := jpeg.Decode(bytes.NewReader(jpegBytes))
	if err != nil {
		return
	}

	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	gray := make([]uint8, w*h)

	idx := 0
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			lum := uint8(0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8))
			gray[idx] = lum
			idx++
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.latestJPEG = append([]byte(nil), jpegBytes...)

	if len(m.prevGray) == len(gray) && m.width == w && m.height == h {
		changedPixels := 0
		totalPixels := len(gray)
		for i := 0; i < totalPixels; i++ {
			diff := math.Abs(float64(gray[i]) - float64(m.prevGray[i]))
			if diff > 28 {
				changedPixels++
			}
		}
		changeRatio := float64(changedPixels) / float64(totalPixels)

		if changeRatio > 0.04 && time.Since(m.lastAlert) > 15*time.Second {
			m.lastAlert = time.Now()
			m.alertCount++
			filename := m.saveSnapshotLocked(jpegBytes, m.lastAlert)
			m.lastAlertFile = filename
			log.Printf("[INTRUSION ALERT #%d] Camera %s | Motion: %.2f%% | Snapshot: %s",
				m.alertCount, m.cfg.IP, changeRatio*100, filename)
		}
	}

	m.prevGray = gray
	m.width = w
	m.height = h
}

func (m *Monitor) saveSnapshotLocked(jpegBytes []byte, ts time.Time) string {
	_ = os.MkdirAll("alerts", 0755)
	name := fmt.Sprintf("intrusion_%s.jpg", ts.Format("20060102_150405"))
	fullPath := filepath.Join("alerts", name)
	if err := os.WriteFile(fullPath, jpegBytes, 0644); err != nil {
		log.Printf("Failed to save snapshot: %v", err)
	}
	return fullPath
}

func (m *Monitor) streamMJPEG(ctx context.Context) {
	client := &http.Client{Timeout: 0}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.MJPEGURL, nil)
		if err != nil {
			log.Printf("Invalid MJPEG URL: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("MJPEG connection error (%s): %v; retrying in 3s...", m.cfg.IP, err)
			time.Sleep(3 * time.Second)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("MJPEG unexpected status (%s): %s; retrying in 3s...", m.cfg.IP, resp.Status)
			_ = resp.Body.Close()
			time.Sleep(3 * time.Second)
			continue
		}

		contentType := resp.Header.Get("Content-Type")
		boundary := extractBoundary(contentType)
		if boundary == "" {
			log.Printf("No multipart boundary in Content-Type: %q", contentType)
			_ = resp.Body.Close()
			time.Sleep(3 * time.Second)
			continue
		}

		mr := multipart.NewReader(resp.Body, boundary)
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(part); err == nil && buf.Len() > 0 {
				m.processFrame(buf.Bytes())
			}
		}
		_ = resp.Body.Close()
		time.Sleep(2 * time.Second)
	}
}

func extractBoundary(contentType string) string {
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "boundary=") {
			return strings.Trim(strings.TrimPrefix(part, "boundary="), `"`)
		}
	}
	return ""
}

func (m *Monitor) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	frame := append([]byte(nil), m.latestJPEG...)
	m.mu.RUnlock()

	if len(frame) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(frame)
}

func (m *Monitor) handleStatus(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"camera_ip":%q,"alert_count":%d,"last_alert_time":%q,"last_snapshot":%q}`,
		m.cfg.IP,
		m.alertCount,
		m.lastAlert.Format(time.RFC3339),
		m.lastAlertFile,
	)
}

func (m *Monitor) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html>
<head><meta charset="utf-8"><title>CCTV Intrusion Monitor</title></head>
<body style="font-family:sans-serif;background:#111;color:#eee;padding:20px;">
  <h2>Camera Monitor (%s)</h2>
  <p id="status">Loading status...</p>
  <img id="cam" src="/snapshot.jpg" style="max-width:900px;width:100%%;border:2px solid #444;" />
  <script>
    setInterval(() => {
      document.getElementById("cam").src = "/snapshot.jpg?t=" + Date.now();
      fetch("/status").then(r => r.json()).then(d => {
        document.getElementById("status").innerText =
          "Alerts: " + d.alert_count + " | Last Alert: " + d.last_alert_time + " | Snapshot: " + d.last_snapshot;
      });
    }, 1000);
  </script>
</body>
</html>`, m.cfg.IP)
}

func main() {
	if err := loadEnvFile(".env"); err != nil {
		log.Fatalf("Failed to load .env: %v", err)
	}

	cfg := loadConfig()
	mon := &Monitor{cfg: cfg}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go mon.streamMJPEG(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", mon.handleDashboard)
	mux.HandleFunc("/snapshot.jpg", mon.handleSnapshot)
	mux.HandleFunc("/status", mon.handleStatus)

	log.Printf("Monitoring camera %s (RTSP: %s) | Laptop UI: http://localhost%s",
		cfg.IP, cfg.RTSPURL, cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
