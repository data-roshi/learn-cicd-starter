package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	expectedKey := ""
	expectedErr := ErrNoAuthHeaderIncluded

	apiKey, err := GetAPIKey(headers)
	if apiKey != expectedKey {
		t.Errorf("expected %v, got %v", expectedKey, apiKey)
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestGetAPIKey_MalformedAuthorizationHeader(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"Bearer token"},
	}
	expectedKey := ""
	expectedErr := errors.New("malformed authorization header")

	apiKey, err := GetAPIKey(headers)
	if apiKey != expectedKey {
		t.Errorf("expected %v, got %v", expectedKey, apiKey)
	}
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestGetAPIKey_ValidAuthorizationHeader(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"ApiKey my-secret-key"},
	}
	expectedKey := "my-secret-key"
	expectedErr := error(nil) // Explicitly set to nil

	apiKey, err := GetAPIKey(headers)
	if apiKey != expectedKey {
		t.Errorf("expected %v, got %v", expectedKey, apiKey)
	}
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}
