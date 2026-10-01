package workload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Validator struct {
	apiURL            string
	reviewerTokenFile string
	audience          string
	expectedUsers     map[string]struct{}
	client            *http.Client
}

func New(apiURL, tokenFile, caFile, audience, namespace string, serviceAccounts []string, timeout time.Duration) (*Validator, error) {
	reviewerToken, err := readFileScoped(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read kubernetes service account token: %w", err)
	}
	if strings.TrimSpace(string(reviewerToken)) == "" {
		return nil, errors.New("kubernetes service account token is empty")
	}
	caPEM, err := readFileScoped(caFile)
	if err != nil {
		return nil, fmt.Errorf("read kubernetes CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse kubernetes CA")
	}
	expectedUsers := make(map[string]struct{}, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		serviceAccount = strings.TrimSpace(serviceAccount)
		if serviceAccount != "" {
			expectedUsers[fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount)] = struct{}{}
		}
	}
	return &Validator{
		apiURL:            strings.TrimRight(apiURL, "/"),
		reviewerTokenFile: filepath.Clean(tokenFile),
		audience:          audience,
		expectedUsers:     expectedUsers,
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

func readFileScoped(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	name := filepath.Base(clean)
	if name == "." || name == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid file path %q", path)
	}
	rootDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

func (v *Validator) Validate(ctx context.Context, token string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", errors.New("workload token is required")
	}
	reviewerToken, err := readFileScoped(v.reviewerTokenFile)
	if err != nil {
		return "", fmt.Errorf("read kubernetes service account token: %w", err)
	}
	reviewerAuthorization := strings.TrimSpace(string(reviewerToken))
	if reviewerAuthorization == "" {
		return "", errors.New("kubernetes service account token is empty")
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec": map[string]any{
			"token": token, "audiences": []string{v.audience},
		},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.apiURL+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reviewerAuthorization)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kubernetes token review: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("kubernetes token review returned status %d", resp.StatusCode)
	}
	var result struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if _, ok := v.expectedUsers[result.Status.User.Username]; !result.Status.Authenticated || !ok {
		return "", errors.New("unexpected workload identity")
	}
	foundAudience := false
	for _, audience := range result.Status.Audiences {
		if audience == v.audience {
			foundAudience = true
			break
		}
	}
	if !foundAudience {
		return "", errors.New("workload audience mismatch")
	}
	return result.Status.User.Username, nil
}
