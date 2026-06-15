package workload

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptsExpectedServiceAccountAndAudience(t *testing.T) {
	client := &http.Client{
		Timeout: time.Second,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Authorization") != "Bearer reviewer" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			return jsonResponse(`{"status":{"authenticated":true,"audiences":["incident-audience"],"user":{"username":"system:serviceaccount:dendenmushi:incident-agent"}}}`), nil
		}),
	}
	validator := &Validator{
		apiURL: "https://kubernetes.test", reviewerToken: "reviewer", audience: "incident-audience",
		expectedUser: "system:serviceaccount:dendenmushi:incident-agent",
		client:       client,
	}
	subject, err := validator.Validate(t.Context(), "projected-token")
	if err != nil {
		t.Fatal(err)
	}
	if subject != validator.expectedUser {
		t.Fatalf("subject = %q", subject)
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	validator := &Validator{
		apiURL: "https://kubernetes.test", reviewerToken: "reviewer", audience: "incident-audience",
		expectedUser: "system:serviceaccount:dendenmushi:incident-agent",
		client: &http.Client{
			Timeout: time.Second,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(`{"status":{"authenticated":true,"audiences":["other"],"user":{"username":"system:serviceaccount:dendenmushi:incident-agent"}}}`), nil
			}),
		},
	}
	if _, err := validator.Validate(t.Context(), "projected-token"); err == nil {
		t.Fatal("TokenReview accepted the wrong audience")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
