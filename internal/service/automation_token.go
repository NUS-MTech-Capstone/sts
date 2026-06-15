package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/golang-jwt/jwt/v5"
)

type automationClaims struct {
	TokenUse           string   `json:"tokenUse"`
	RunID              string   `json:"runId"`
	IncidentID         string   `json:"incidentId"`
	HostID             string   `json:"hostId"`
	Phase              string   `json:"phase"`
	AllowedOperations  []string `json:"allowedOperations"`
	PlanHash           string   `json:"planHash,omitempty"`
	OwnerPodID         string   `json:"ownerPodId"`
	OwnerInstanceID    string   `json:"ownerInstanceId"`
	Address            string   `json:"address"`
	Username           string   `json:"username"`
	CredentialSecretID string   `json:"credentialSecretId"`
	HostPublicKey      string   `json:"hostPublicKey"`
	ServiceName        string   `json:"serviceName"`
	HealthURL          string   `json:"healthUrl"`
	HelperPath         string   `json:"helperPath"`
	jwt.RegisteredClaims
}

func (s *Service) IssueAutomationToken(ctx context.Context, workloadToken string, req model.AutomationTokenRequest) (model.AutomationTokenResponse, error) {
	if s.workloads == nil {
		return model.AutomationTokenResponse{}, errors.New("automation workload validation is not configured")
	}
	subject, err := s.workloads.Validate(ctx, workloadToken)
	if err != nil {
		return model.AutomationTokenResponse{}, errors.New("workload identity is not authorized")
	}
	if req.RunID == "" || req.IncidentID == "" || req.HostID == "" || req.OwnerPodID == "" || req.OwnerInstanceID == "" {
		return model.AutomationTokenResponse{}, errors.New("run, incident, host and owner metadata are required")
	}
	if req.Phase != "diagnose" && req.Phase != "remediate" && req.Phase != "verify" {
		return model.AutomationTokenResponse{}, errors.New("phase must be diagnose, remediate or verify")
	}
	if req.Phase == "remediate" && req.PlanHash == "" {
		return model.AutomationTokenResponse{}, errors.New("planHash is required for remediation")
	}
	if len(req.AllowedOperations) == 0 || len(req.AllowedOperations) > 16 {
		return model.AutomationTokenResponse{}, errors.New("allowedOperations must contain between 1 and 16 operations")
	}
	if s.serverInventory == nil {
		return model.AutomationTokenResponse{}, errors.New("server inventory is required")
	}
	server, err := s.serverInventory.Get(ctx, req.HostID)
	if err != nil {
		return model.AutomationTokenResponse{}, err
	}
	if server.Address == "" || server.Username == "" || server.CredentialSecretID == "" || server.HostPublicKey == "" {
		return model.AutomationTokenResponse{}, errors.New("server inventory ssh target is incomplete")
	}
	if server.Automation.ServiceName == "" || server.Automation.HelperPath == "" || len(server.Automation.AllowedOperations) == 0 {
		return model.AutomationTokenResponse{}, errors.New("server inventory automation profile is incomplete")
	}
	allowed := make([]string, 0, len(req.AllowedOperations))
	seen := make(map[string]struct{}, len(req.AllowedOperations))
	for _, operation := range req.AllowedOperations {
		operation = strings.TrimSpace(operation)
		if operation == "" || !slices.Contains(server.Automation.AllowedOperations, operation) {
			return model.AutomationTokenResponse{}, errors.New("requested operation is not allowed by inventory")
		}
		if _, ok := seen[operation]; ok {
			continue
		}
		seen[operation] = struct{}{}
		allowed = append(allowed, operation)
	}
	jwtID, err := randomID()
	if err != nil {
		return model.AutomationTokenResponse{}, err
	}
	issuedAt := s.now().UTC().Truncate(jwt.TimePrecision)
	ttl := s.tokenConfig.AutomationTTL
	if ttl <= 0 {
		ttl = s.tokenConfig.TTL
	}
	expiresAt := issuedAt.Add(ttl)
	claims := automationClaims{
		TokenUse: "automation", RunID: req.RunID, IncidentID: req.IncidentID, HostID: req.HostID,
		Phase: req.Phase, AllowedOperations: allowed, PlanHash: req.PlanHash,
		OwnerPodID: req.OwnerPodID, OwnerInstanceID: req.OwnerInstanceID,
		Address: server.Address, Username: server.Username,
		CredentialSecretID: server.CredentialSecretID, HostPublicKey: server.HostPublicKey,
		ServiceName: server.Automation.ServiceName, HealthURL: server.Automation.HealthURL,
		HelperPath: server.Automation.HelperPath,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: s.tokenConfig.Issuer, Subject: subject,
			Audience:  jwt.ClaimStrings{s.tokenConfig.Audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt), NotBefore: jwt.NewNumericDate(issuedAt),
			IssuedAt: jwt.NewNumericDate(issuedAt), ID: jwtID,
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.tokenConfig.SigningKey)
	if err != nil {
		return model.AutomationTokenResponse{}, err
	}
	return model.AutomationTokenResponse{TokenType: "Bearer", CapabilityToken: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) ValidateAutomationToken(_ context.Context, req model.AutomationTokenValidateRequest) model.AutomationValidateResponse {
	if req.Token == "" || req.RunID == "" {
		return model.AutomationValidateResponse{Allowed: false, Reason: "runId and token are required"}
	}
	claims := &automationClaims{}
	token, err := jwt.ParseWithClaims(
		req.Token, claims, func(_ *jwt.Token) (any, error) { return s.tokenConfig.SigningKey, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(s.tokenConfig.Issuer), jwt.WithAudience(s.tokenConfig.Audience),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(s.tokenConfig.ClockSkew),
		jwt.WithTimeFunc(s.now), jwt.WithStrictDecoding(),
	)
	if err != nil || !token.Valid {
		return model.AutomationValidateResponse{Allowed: false, Reason: "invalid or expired token"}
	}
	if claims.TokenUse != "automation" || claims.RunID == "" || claims.IncidentID == "" ||
		claims.HostID == "" || claims.Subject == "" || claims.OwnerPodID == "" ||
		claims.OwnerInstanceID == "" || claims.Address == "" || claims.Username == "" ||
		claims.CredentialSecretID == "" || claims.HostPublicKey == "" ||
		claims.ServiceName == "" || claims.HelperPath == "" || len(claims.AllowedOperations) == 0 {
		return model.AutomationValidateResponse{Allowed: false, Reason: "invalid automation claims"}
	}
	if subtle.ConstantTimeCompare([]byte(claims.RunID), []byte(req.RunID)) != 1 {
		return model.AutomationValidateResponse{Allowed: false, Reason: "token run mismatch"}
	}
	return model.AutomationValidateResponse{Allowed: true, Claims: &model.AutomationClaims{
		RunID: claims.RunID, IncidentID: claims.IncidentID, HostID: claims.HostID,
		Phase: claims.Phase, AllowedOperations: claims.AllowedOperations, PlanHash: claims.PlanHash,
		OwnerPodID: claims.OwnerPodID, OwnerInstanceID: claims.OwnerInstanceID,
		Address: claims.Address, Username: claims.Username,
		CredentialSecretID: claims.CredentialSecretID, HostPublicKey: claims.HostPublicKey,
		ServiceName: claims.ServiceName, HealthURL: claims.HealthURL, HelperPath: claims.HelperPath,
	}}
}
