package workload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
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
		expectedUsers: map[string]struct{}{
			"system:serviceaccount:dendenmushi:incident-agent":     {},
			"system:serviceaccount:dendenmushi:agent-controlplane": {},
		},
		client: client,
	}
	subject, err := validator.Validate(t.Context(), "projected-token")
	if err != nil {
		t.Fatal(err)
	}
	if subject != "system:serviceaccount:dendenmushi:incident-agent" {
		t.Fatalf("subject = %q", subject)
	}
}

func TestValidateAcceptsAgentControlplaneServiceAccount(t *testing.T) {
	validator := &Validator{
		apiURL: "https://kubernetes.test", reviewerToken: "reviewer", audience: "incident-audience",
		expectedUsers: map[string]struct{}{
			"system:serviceaccount:dendenmushi:incident-agent":     {},
			"system:serviceaccount:dendenmushi:agent-controlplane": {},
		},
		client: &http.Client{
			Timeout: time.Second,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(`{"status":{"authenticated":true,"audiences":["incident-audience"],"user":{"username":"system:serviceaccount:dendenmushi:agent-controlplane"}}}`), nil
			}),
		},
	}
	subject, err := validator.Validate(t.Context(), "projected-token")
	if err != nil {
		t.Fatal(err)
	}
	if subject != "system:serviceaccount:dendenmushi:agent-controlplane" {
		t.Fatalf("subject = %q", subject)
	}
}

func TestValidateRejectsWrongAudience(t *testing.T) {
	validator := &Validator{
		apiURL: "https://kubernetes.test", reviewerToken: "reviewer", audience: "incident-audience",
		expectedUsers: map[string]struct{}{"system:serviceaccount:dendenmushi:incident-agent": {}},
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

func TestNewReadsTokenAndCAFiles(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tokenFile, []byte("reviewer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}

	validator, err := New("https://kubernetes.test/", tokenFile, caFile, "aud", "ns", []string{"sa", "agent-controlplane"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if validator.apiURL != "https://kubernetes.test" || validator.reviewerToken != "reviewer" ||
		len(validator.expectedUsers) != 2 {
		t.Fatalf("validator = %#v", validator)
	}
}

func TestNewRejectsUnreadableOrInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tokenFile, []byte("reviewer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, []byte("not a ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("https://kubernetes.test", filepath.Join(dir, "missing"), caFile, "aud", "ns", []string{"sa"}, time.Second); err == nil {
		t.Fatal("New() accepted missing token file")
	}
	if _, err := New("https://kubernetes.test", tokenFile, caFile, "aud", "ns", []string{"sa"}, time.Second); err == nil {
		t.Fatal("New() accepted invalid CA")
	}
}

func TestValidateRejectsEmptyTokenStatusAndTransportFailures(t *testing.T) {
	validator := &Validator{
		apiURL: "https://kubernetes.test", reviewerToken: "reviewer", audience: "incident-audience",
		expectedUsers: map[string]struct{}{"system:serviceaccount:dendenmushi:incident-agent": {}},
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network down")
		})},
	}
	if _, err := validator.Validate(t.Context(), " "); err == nil {
		t.Fatal("Validate() accepted empty workload token")
	}
	if _, err := validator.Validate(t.Context(), "projected-token"); err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("Validate() error = %v, want transport error", err)
	}

	validator.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	if _, err := validator.Validate(t.Context(), "projected-token"); err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("Validate() error = %v, want status error", err)
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

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
