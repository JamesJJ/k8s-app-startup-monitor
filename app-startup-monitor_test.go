package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func init() {
	logInit()

}

func TestMaxString_short(t *testing.T) {
	input := "hello, good bye   "
	want := input
	got := MaxString(input, 30, false)
	if got != want {
		t.Errorf("MaxString(\"%s\") = %s; want \"%s\"", input, got, want)
	}
}

func TestMaxString_whitespace(t *testing.T) {
	input := "hello, good bye   "
	want := "hello, good bye"
	got := MaxString(input, 30, true)
	if got != want {
		t.Errorf("MaxString(\"%s\") = %s; want \"%s\"", input, got, want)
	}
}

func TestMaxString_long(t *testing.T) {
	input := "hello, good bye   "
	want := "hell"
	got := MaxString(input, 4, false)
	if got != want {
		t.Errorf("MaxString(\"%s\") = %s; want \"%s\"", input, got, want)
	}
}

func TestSecretsDirectory(t *testing.T) {
	_ = os.Setenv("ASM_SECRETS_DIR", "/tmp/")
	want := "/tmp"
	got := SecretsDirectory()
	if got != want {
		t.Errorf("SecretsDir() = %s; want \"%s\"", got, want)
	}
}

func TestHealthAPI(t *testing.T) {

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(HealthCheckHandler)

	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("HealthCheckHandler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	wantct := "application/json"
	if ct := rr.Header().Get("content-type"); ct != wantct {
		t.Errorf("HealthCheckHandler returned wrong content-type: got %v want %v",
			ct, wantct)
	}
}
