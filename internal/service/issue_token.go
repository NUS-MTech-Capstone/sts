package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/NUS-MTech-Capstone/sts/internal/model"
	"github.com/golang-jwt/jwt/v5"
)

type sessionClaims struct {
	TokenUse           string `json:"tokenUse"`
	HostID             string `json:"hostId"`
	CRID               string `json:"crId"`
	ConnectionType     string `json:"connectionType"`
	Action             string `json:"action"`
	Mode               string `json:"mode"`
	Address            string `json:"address,omitempty"`
	Username           string `json:"username,omitempty"`
	CredentialSecretID string `json:"credentialSecretId,omitempty"`
	HostPublicKey      string `json:"hostPublicKey,omitempty"`
	SessionID          string `json:"sessionId"`
	jwt.RegisteredClaims
}

func (s *Service) IssueSessionToken(ctx context.Context, req model.SessionTokenRequest) (model.SessionTokenResponse, error) {
	if req.SessionID == "" || req.UserID == "" || req.HostID == "" || req.CRID == "" {
		return model.SessionTokenResponse{}, errors.New("sessionId, userId, hostId and crId are required")
	}
	if req.ConnectionType == "" {
		req.ConnectionType = "ssh"
	}
	if !validActionMode(req.Action, req.Mode) {
		return model.SessionTokenResponse{}, errors.New("invalid action and mode combination")
	}
	if req.ConnectionType != "ssh" {
		return model.SessionTokenResponse{}, errors.New("only ssh connectionType is supported")
	}
	if s.serverInventory == nil {
		return model.SessionTokenResponse{}, errors.New("server inventory is required to issue ssh session tokens")
	}
	server, err := s.serverInventory.Get(ctx, req.HostID)
	if err != nil {
		return model.SessionTokenResponse{}, err
	}
	if server.HostID != "" && server.HostID != req.HostID {
		return model.SessionTokenResponse{}, errors.New("server inventory hostId mismatch")
	}
	if server.ConnectionType == "" {
		server.ConnectionType = "ssh"
	}
	if server.ConnectionType != req.ConnectionType {
		return model.SessionTokenResponse{}, errors.New("server inventory connectionType mismatch")
	}
	if server.Address == "" || server.Username == "" || server.CredentialSecretID == "" || server.HostPublicKey == "" {
		return model.SessionTokenResponse{}, errors.New("server inventory ssh target is incomplete")
	}

	jwtID, err := randomID()
	if err != nil {
		return model.SessionTokenResponse{}, err
	}

	issuedAt := s.now().UTC().Truncate(jwt.TimePrecision)
	expiresAt := issuedAt.Add(s.tokenConfig.TTL)
	claims := sessionClaims{
		TokenUse:           "session",
		SessionID:          req.SessionID,
		HostID:             req.HostID,
		CRID:               req.CRID,
		ConnectionType:     req.ConnectionType,
		Action:             req.Action,
		Mode:               req.Mode,
		Address:            server.Address,
		Username:           server.Username,
		CredentialSecretID: server.CredentialSecretID,
		HostPublicKey:      server.HostPublicKey,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.tokenConfig.Issuer,
			Subject:   req.UserID,
			Audience:  jwt.ClaimStrings{s.tokenConfig.Audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ID:        jwtID,
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.tokenConfig.SigningKey)
	if err != nil {
		return model.SessionTokenResponse{}, err
	}

	return model.SessionTokenResponse{
		TokenType:    "Bearer",
		SessionToken: token,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) ValidateSessionToken(_ context.Context, req model.TokenValidateRequest) model.ValidateResponse {
	if req.Token == "" {
		return model.ValidateResponse{Allowed: false, Reason: "token is required"}
	}
	if req.SessionID == "" {
		return model.ValidateResponse{Allowed: false, Reason: "sessionId is required"}
	}

	claims := &sessionClaims{}
	token, err := jwt.ParseWithClaims(
		req.Token,
		claims,
		func(_ *jwt.Token) (any, error) {
			return s.tokenConfig.SigningKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(s.tokenConfig.Issuer),
		jwt.WithAudience(s.tokenConfig.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(s.tokenConfig.ClockSkew),
		jwt.WithTimeFunc(s.now),
		jwt.WithStrictDecoding(),
	)
	if err != nil || !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return model.ValidateResponse{Allowed: false, Reason: "token expired"}
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return model.ValidateResponse{Allowed: false, Reason: "token not active"}
		}
		return model.ValidateResponse{Allowed: false, Reason: "invalid token"}
	}
	if claims.TokenUse != "session" || claims.Subject == "" || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ID == "" ||
		claims.SessionID == "" || claims.HostID == "" || claims.CRID == "" || claims.ConnectionType == "" ||
		!validActionMode(claims.Action, claims.Mode) {
		return model.ValidateResponse{Allowed: false, Reason: "invalid token claims"}
	}
	if claims.SessionID != req.SessionID {
		return model.ValidateResponse{Allowed: false, Reason: "token session mismatch"}
	}
	if req.UserID != "" && claims.Subject != req.UserID {
		return model.ValidateResponse{Allowed: false, Reason: "token user mismatch"}
	}
	if req.HostID != "" && claims.HostID != req.HostID {
		return model.ValidateResponse{Allowed: false, Reason: "token host mismatch"}
	}
	if req.CRID != "" && claims.CRID != req.CRID {
		return model.ValidateResponse{Allowed: false, Reason: "token change request mismatch"}
	}
	if req.ConnectionType != "" && claims.ConnectionType != req.ConnectionType {
		return model.ValidateResponse{Allowed: false, Reason: "token connectionType mismatch"}
	}
	if req.Action != "" && claims.Action != req.Action {
		return model.ValidateResponse{Allowed: false, Reason: "token action mismatch"}
	}
	if req.Mode != "" && claims.Mode != req.Mode {
		return model.ValidateResponse{Allowed: false, Reason: "token mode mismatch"}
	}
	if claims.ConnectionType == "ssh" &&
		(claims.Address == "" || claims.Username == "" || claims.CredentialSecretID == "" || claims.HostPublicKey == "") {
		return model.ValidateResponse{Allowed: false, Reason: "invalid ssh target claims"}
	}
	return model.ValidateResponse{
		Allowed: true,
		Claims: &model.SessionClaims{
			SessionID:          claims.SessionID,
			UserID:             claims.Subject,
			HostID:             claims.HostID,
			CRID:               claims.CRID,
			ConnectionType:     claims.ConnectionType,
			Action:             claims.Action,
			Mode:               claims.Mode,
			Address:            claims.Address,
			Username:           claims.Username,
			CredentialSecretID: claims.CredentialSecretID,
			HostPublicKey:      claims.HostPublicKey,
		},
	}
}

func validActionMode(action, mode string) bool {
	return action == "start" && mode == "owner" ||
		action == "rejoin" && mode == "owner" ||
		action == "observe" && mode == "observer"
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
