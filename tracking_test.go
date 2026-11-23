package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleTrackingRequestUsesDirectPeerIP(t *testing.T) {
	originalWriter := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(originalWriter)

	request := httptest.NewRequest(http.MethodGet, "/track", nil)
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	response := httptest.NewRecorder()

	handleTrackingRequest(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Body.String(); got != "Access Logged" {
		t.Errorf("body = %q, want %q", got, "Access Logged")
	}
	if !strings.Contains(logged.String(), "192.0.2.10") {
		t.Errorf("log = %q, want direct peer IP", logged.String())
	}
	if strings.Contains(logged.String(), "203.0.113.99") {
		t.Errorf("log = %q, must not trust X-Forwarded-For", logged.String())
	}
}

func TestTrackingHandlerOnlyServesTrackPath(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/other", nil)
	response := httptest.NewRecorder()

	newTrackingHandler().ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestLocationExampleReturnsStaticJSON(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/location-example", nil)
	response := httptest.NewRecorder()

	newTrackingHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var got struct {
		IP          string  `json:"ip"`
		City        string  `json:"city"`
		Region      string  `json:"region"`
		CountryName string  `json:"country_name"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode location example: %v", err)
	}
	if got.IP != "197.210.x.x" || got.City != "Lagos" || got.Region != "Lagos" ||
		got.CountryName != "Nigeria" || got.Latitude != 6.5244 || got.Longitude != 3.3792 {
		t.Errorf("location example = %+v, want supplied static example", got)
	}
}

func TestHandleTrackClickRedirectsAndRecordsClick(t *testing.T) {
	originalWriter := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(originalWriter)

	store := &trackingLinkStore{
		links: map[string]TrackingLink{
			"token-123": {
				ID:        "token-123",
				TargetURL: "https://example.org/destination",
			},
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/click?token=token-123", nil)
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("User-Agent", "tracking-test")
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	response := httptest.NewRecorder()

	handleTrackClick(store, response, request)

	if response.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", response.Code, http.StatusFound)
	}
	if got := response.Header().Get("Location"); got != "https://example.org/destination" {
		t.Errorf("Location = %q, want destination URL", got)
	}
	if got := store.links["token-123"].ClickCount; got != 1 {
		t.Errorf("click count = %d, want 1", got)
	}
	if !strings.Contains(logged.String(), "192.0.2.10") ||
		!strings.Contains(logged.String(), `user_agent="tracking-test"`) ||
		!strings.Contains(logged.String(), "timestamp=") {
		t.Errorf("log = %q, want client IP, user agent, and timestamp", logged.String())
	}
	if strings.Contains(logged.String(), "203.0.113.99") {
		t.Errorf("log = %q, must not trust X-Forwarded-For", logged.String())
	}
}

func TestHandleTrackClick(t *testing.T) {
	token, err := CreateTrackingLink("https://example.org/destination")
	if err != nil {
		t.Fatalf("CreateTrackingLink() error = %v", err)
	}
	defer func() {
		defaultTrackingLinkStore.mu.Lock()
		delete(defaultTrackingLinkStore.links, token)
		defaultTrackingLinkStore.mu.Unlock()
	}()

	request := httptest.NewRequest(http.MethodGet, "/track?token="+token, nil)
	response := httptest.NewRecorder()

	HandleTrackClick(response, request)

	if response.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", response.Code, http.StatusFound)
	}
	if got := response.Header().Get("Location"); got != "https://example.org/destination" {
		t.Errorf("Location = %q, want destination URL", got)
	}
}

func TestHandleTrackClickRejectsMissingAndUnknownTokens(t *testing.T) {
	store := &trackingLinkStore{links: make(map[string]TrackingLink)}

	for _, test := range []struct {
		name string
		url  string
		want int
	}{
		{name: "missing token", url: "/click", want: http.StatusBadRequest},
		{name: "unknown token", url: "/click?token=unknown", want: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handleTrackClick(store, response, httptest.NewRequest(http.MethodGet, test.url, nil))
			if response.Code != test.want {
				t.Errorf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestCreateTrackingLinkValidatesTargetAndEnablesClickRoute(t *testing.T) {
	for _, targetURL := range []string{
		"javascript:alert(1)",
		"//example.org/destination",
		"https://user:password@example.org/destination",
	} {
		if _, err := CreateTrackingLink(targetURL); err == nil {
			t.Errorf("CreateTrackingLink(%q) succeeded, want error", targetURL)
		}
	}

	token, err := CreateTrackingLink("https://example.org/destination")
	if err != nil {
		t.Fatalf("CreateTrackingLink() error = %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64 hexadecimal characters", len(token))
	}

	request := httptest.NewRequest(http.MethodGet, "/click?token="+token, nil)
	response := httptest.NewRecorder()
	newTrackingHandler().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", response.Code, http.StatusFound)
	}
	if got := response.Header().Get("Location"); got != "https://example.org/destination" {
		t.Errorf("Location = %q, want destination URL", got)
	}
}

func TestGenerateTrackingTokenRequiresPositiveLength(t *testing.T) {
	for _, length := range []int{0, -1} {
		if _, err := GenerateTrackingToken(length); err == nil {
			t.Errorf("GenerateTrackingToken(%d) succeeded, want error", length)
		}
	}
}
