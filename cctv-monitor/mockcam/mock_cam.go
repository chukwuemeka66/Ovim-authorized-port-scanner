package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"log"
	"net/http"
	"time"
)

func makeFrame(tick int) ([]byte, error) {
	const width, height = 320, 240
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 30, G: 35, B: 45, A: 255})
		}
	}

	if tick%8 == 0 {
		for y := 40; y < 200; y++ {
			for x := 60; x < 260; x++ {
				img.Set(x, y, color.RGBA{R: 230, G: 230, B: 230, A: 255})
			}
		}
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		return nil, fmt.Errorf("encode mock camera frame: %w", err)
	}
	return buf.Bytes(), nil
}

func mjpegHandler(w http.ResponseWriter, r *http.Request) {
	const boundary = "frame"
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary="+boundary)

	flusher, canFlush := w.(http.Flusher)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for tick := 1; ; tick++ {
		jpg, err := makeFrame(tick)
		if err != nil {
			log.Printf("Failed to generate mock frame: %v", err)
			return
		}

		if _, err := fmt.Fprintf(w, "--%s\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", boundary, len(jpg)); err != nil {
			return
		}
		if _, err := w.Write(jpg); err != nil {
			return
		}
		if _, err := fmt.Fprint(w, "\r\n"); err != nil {
			return
		}
		if canFlush {
			flusher.Flush()
		}

		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/mjpeg", mjpegHandler)

	const addr = "127.0.0.1:9000"
	log.Printf("Mock CCTV MJPEG stream running at http://%s/mjpeg", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Mock camera server error: %v", err)
	}
}
