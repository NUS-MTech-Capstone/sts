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
	SessionID string `json:"sessionId"`
	Mode      string `json:"mode"`
	jwt.RegisteredClaims
}

func (s *Service) IssueSessionToken(_ context.Context, req model.SessionTokenRequest) (model.SessionTokenResponse, error) {
	if req.SessionID == "" || req.UserID == "" {
		return model.SessionTokenResponse{}, errors.New("sessionId and userId are required")
	}
	if req.Mode != "owner" && req.Mode != "observer" {
		return model.SessionTokenResponse{}, errors.New("mode must be owner or observer")
	}

	jwtID, err := randomID()
	if err != nil {
		return model.SessionTokenResponse{}, err
	}

	issuedAt := s.now().UTC().Truncate(jwt.TimePrecision)
	expiresAt := issuedAt.Add(s.tokenConfig.TTL)
	claims := sessionClaims{
		SessionID: req.SessionID,
		Mode:      req.Mode,
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
	if claims.Subject == "" || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ID == "" ||
		claims.SessionID == "" || (claims.Mode != "owner" && claims.Mode != "observer") {
		return model.ValidateResponse{Allowed: false, Reason: "invalid token claims"}
	}
	if claims.SessionID != req.SessionID {
		return model.ValidateResponse{Allowed: false, Reason: "token session mismatch"}
	}
	if req.UserID != "" && claims.Subject != req.UserID {
		return model.ValidateResponse{Allowed: false, Reason: "token user mismatch"}
	}
	if req.Mode != "" && claims.Mode != req.Mode {
		return model.ValidateResponse{Allowed: false, Reason: "token mode mismatch"}
	}
	return model.ValidateResponse{Allowed: true}
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
