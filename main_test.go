package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendLogSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Splunk test-token")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer ts.Close()

	resp, err := sendLog(ts.URL, "test-token", ts.Client(), []byte(`{"status":"test"}`))
	if err != nil {
		t.Fatalf("sendLog() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestSendLogWithoutToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want no authorization header", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	resp, err := sendLog(ts.URL, "", ts.Client(), []byte(`{"status":"test"}`))
	if err != nil {
		t.Fatalf("sendLog() error = %v", err)
	}
	resp.Body.Close()
}

func TestSendLogToSplunkHEC(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Splunk test-token")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var payload struct {
			Time       int64  `json:"time"`
			Host       string `json:"host"`
			Sourcetype string `json:"sourcetype"`
			Event      struct {
				Timestamp string `json:"timestamp"`
				EventType string `json:"event_type"`
				Status    string `json:"status"`
			} `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode HEC payload: %v", err)
		}
		if payload.Time == 0 || payload.Host != "local-scanner-node" || payload.Sourcetype != "ovimscannerjson" {
			t.Errorf("HEC metadata = %+v, want timestamp, local-scanner-node, ovimscannerjson", payload)
		}
		if payload.Event.EventType != "SECURITY_SCAN_EVENT" || payload.Event.Status != "SUCCESS" {
			t.Errorf("event = %+v, want SECURITY_SCAN_EVENT/SUCCESS", payload.Event)
		}
		if _, err := time.Parse(time.RFC3339, payload.Event.Timestamp); err != nil {
			t.Errorf("event timestamp %q is not RFC3339: %v", payload.Event.Timestamp, err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	resp, err := SendLogToSplunkHEC(ts.URL, "test-token", "SECURITY_SCAN_EVENT", "SUCCESS")
	if err != nil {
		t.Fatalf("SendLogToSplunkHEC() error = %v", err)
	}
	resp.Body.Close()
}

func TestSecurityEventJSON(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	event := SecurityEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "SECURITY_SCAN_EVENT",
		Status:    "SUCCESS",
	}
	after := time.Now().UTC().Add(time.Second)

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal SecurityEvent: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("failed to decode marshaled event: %v", err)
	}

	for _, field := range []string{"timestamp", "event_type", "status"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q", field)
		}
	}

	if got := decoded["event_type"]; got != "SECURITY_SCAN_EVENT" {
		t.Errorf("event_type = %v, want SECURITY_SCAN_EVENT", got)
	}
	if got := decoded["status"]; got != "SUCCESS" {
		t.Errorf("status = %v, want SUCCESS", got)
	}

	parsedTimestamp, err := time.Parse(time.RFC3339, event.Timestamp)
	if err != nil {
		t.Fatalf("timestamp is not RFC3339: %v", err)
	}
	if parsedTimestamp.Before(before) || parsedTimestamp.After(after) {
		t.Errorf("timestamp %v is outside the test interval", parsedTimestamp)
	}
}

func TestPortScanConfigFromEnv(t *testing.T) {
	t.Run("disabled without target", func(t *testing.T) {
		t.Setenv("PORT_SCAN_TARGET", "")

		_, selected, err := portScanConfigFromEnv()
		if err != nil {
			t.Fatalf("portScanConfigFromEnv() error = %v", err)
		}
		if selected {
			t.Fatal("port scan selected without PORT_SCAN_TARGET")
		}
	})

	t.Run("valid loopback configuration", func(t *testing.T) {
		t.Setenv("PORT_SCAN_TARGET", "127.0.0.1")
		t.Setenv("START_PORT", "1")
		t.Setenv("END_PORT", "1024")
		t.Setenv("WORKER_COUNT", "100")

		got, selected, err := portScanConfigFromEnv()
		if err != nil {
			t.Fatalf("portScanConfigFromEnv() error = %v", err)
		}
		if !selected {
			t.Fatal("port scan not selected")
		}
		want := portScanConfig{target: "127.0.0.1", startPort: 1, endPort: 1024, workerCount: 100}
		if got != want {
			t.Errorf("portScanConfigFromEnv() = %+v, want %+v", got, want)
		}
	})

	tests := []struct {
		name        string
		target      string
		startPort   string
		endPort     string
		workerCount string
	}{
		{name: "non-loopback target", target: "192.0.2.1", startPort: "1", endPort: "10", workerCount: "1"},
		{name: "invalid port range", target: "127.0.0.1", startPort: "0", endPort: "10", workerCount: "1"},
		{name: "start port above maximum", target: "127.0.0.1", startPort: "65536", endPort: "65536", workerCount: "1"},
		{name: "invalid worker count", target: "127.0.0.1", startPort: "1", endPort: "10", workerCount: "0"},
		{name: "missing start port", target: "127.0.0.1", endPort: "10", workerCount: "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PORT_SCAN_TARGET", tt.target)
			t.Setenv("START_PORT", tt.startPort)
			t.Setenv("END_PORT", tt.endPort)
			t.Setenv("WORKER_COUNT", tt.workerCount)

			_, selected, err := portScanConfigFromEnv()
			if err == nil {
				t.Fatal("portScanConfigFromEnv() error = nil, want error")
			}
			if !selected {
				t.Fatal("port scan should remain selected for invalid configuration")
			}
		})
	}
}

func TestForwardSecurityEventToDestinations(t *testing.T) {
	var splunkEvent SecurityEvent
	splunkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Splunk splunk-test-token" {
			t.Errorf("Splunk Authorization = %q, want configured HEC token", got)
		}
		var payload hecEvent
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode Splunk payload: %v", err)
		}
		splunkEvent = payload.Event
		w.WriteHeader(http.StatusOK)
	}))
	defer splunkServer.Close()

	var xdrEvent SecurityEvent
	xdrServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer xdr-test-key" {
			t.Errorf("XDR Authorization = %q, want bearer token", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&xdrEvent); err != nil {
			t.Errorf("decode XDR event: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer xdrServer.Close()

	t.Setenv("XDR_ENDPOINT_URL", xdrServer.URL)
	t.Setenv("XDR_API_KEY", "xdr-test-key")
	event := SecurityEvent{
		Timestamp: "2026-11-14T12:00:00Z",
		EventType: "SECURITY_SCAN_EVENT",
		Status:    "SUCCESS",
	}

	resp, err := forwardSecurityEventToDestinations(splunkServer.URL, "splunk-test-token", event)
	if err != nil {
		t.Fatalf("forwardSecurityEventToDestinations() error = %v", err)
	}
	defer resp.Body.Close()

	if splunkEvent != event {
		t.Errorf("Splunk event = %+v, want %+v", splunkEvent, event)
	}
	if xdrEvent != event {
		t.Errorf("XDR event = %+v, want %+v", xdrEvent, event)
	}
}
