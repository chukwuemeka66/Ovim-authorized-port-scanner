package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForwardToXDR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var event SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("decode event: %v", err)
		}
		if event.Source != "scanner" || event.EventID != "event-123" ||
			event.Severity != "high" || event.Details != "suspicious activity" {
			t.Errorf("event = %+v, want forwarded security event fields", event)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	err := ForwardToXDR(server.URL, "test-api-key", SecurityEvent{
		Source:    "scanner",
		EventID:   "event-123",
		Severity:  "high",
		Timestamp: "2026-11-13T12:00:00Z",
		Details:   "suspicious activity",
	})
	if err != nil {
		t.Fatalf("ForwardToXDR() error = %v", err)
	}
}

func TestForwardToXDRReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	err := ForwardToXDR(server.URL, "test-api-key", SecurityEvent{})
	if err == nil || !strings.Contains(err.Error(), "401 Unauthorized") {
		t.Fatalf("ForwardToXDR() error = %v, want HTTP 401 error", err)
	}
}

func TestForwardToXDRRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint string
		apiKey   string
	}{
		{name: "missing API key", endpoint: "https://xdr.example.test/events"},
		{name: "insecure remote URL", endpoint: "http://xdr.example.test/events", apiKey: "test-key"},
		{name: "URL query", endpoint: "https://xdr.example.test/events?token=secret", apiKey: "test-key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ForwardToXDR(test.endpoint, test.apiKey, SecurityEvent{}); err == nil {
				t.Fatal("ForwardToXDR() error = nil, want configuration error")
			}
		})
	}
}

func TestForwardEventsToConfiguredXDR(t *testing.T) {
	var received []SecurityEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		var event SecurityEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("decode event: %v", err)
		}
		received = append(received, event)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	t.Setenv("XDR_ENDPOINT_URL", server.URL)
	t.Setenv("XDR_API_KEY", "test-api-key")

	defaultEvent := SecurityEvent{
		Timestamp: "2026-11-14T12:00:00Z",
		EventType: "SECURITY_SCAN_EVENT",
		Status:    "SUCCESS",
	}
	pathEvents := nodeZeroAttackPathSecurityEvents([]NodeZeroAttackPath{{
		ID:              "path-1",
		Severity:        "High",
		AttackPathTitle: "Example path",
		IPAddress:       "192.0.2.10",
		HostName:        "example.internal",
	}})
	if err := forwardEventsToConfiguredXDR(append([]SecurityEvent{defaultEvent}, pathEvents...)); err != nil {
		t.Fatalf("forwardEventsToConfiguredXDR() error = %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("received %d events, want 2", len(received))
	}
	if received[0] != defaultEvent {
		t.Errorf("first event = %+v, want %+v", received[0], defaultEvent)
	}
	if received[1].EventType != "NODEZERO_ATTACK_PATH" ||
		received[1].Source != "NodeZero" ||
		received[1].EventID != "path-1" ||
		received[1].Severity != "High" ||
		received[1].Timestamp == "" ||
		!strings.Contains(received[1].Details, "example.internal") ||
		!strings.Contains(received[1].Details, "192.0.2.10") {
		t.Errorf("NodeZero event = %+v, want attack-path metadata", received[1])
	}
}

func TestForwardEventsToConfiguredXDRRequiresCompleteConfiguration(t *testing.T) {
	t.Setenv("XDR_ENDPOINT_URL", "https://xdr.example.test/events")
	t.Setenv("XDR_API_KEY", "")

	if err := forwardEventsToConfiguredXDR(nil); err == nil {
		t.Fatal("forwardEventsToConfiguredXDR() error = nil, want incomplete configuration error")
	}
}
