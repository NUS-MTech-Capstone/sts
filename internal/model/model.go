package model

import "time"

type ValidateRequest struct {
	UserID    string `json:"userId"`
	HostID    string `json:"hostId,omitempty"`
	CRID      string `json:"crId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
	Action    string `json:"action"`
}

type ValidateResponse struct {
	Allowed bool           `json:"allowed"`
	Reason  string         `json:"reason,omitempty"`
	Claims  *SessionClaims `json:"claims,omitempty"`
}

type SessionTokenRequest struct {
	SessionID      string `json:"sessionId"`
	UserID         string `json:"userId"`
	HostID         string `json:"hostId"`
	CRID           string `json:"crId"`
	ConnectionType string `json:"connectionType"`
	Action         string `json:"action"`
	Mode           string `json:"mode"`
}

type SessionTokenResponse struct {
	TokenType    string    `json:"tokenType"`
	SessionToken string    `json:"sessionToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type TokenValidateRequest struct {
	SessionID string `json:"sessionId"`
	UserID    string `json:"userId,omitempty"`
	Token     string `json:"token"`
}

type SessionClaims struct {
	SessionID          string `json:"sessionId"`
	UserID             string `json:"userId"`
	HostID             string `json:"hostId"`
	CRID               string `json:"crId"`
	ConnectionType     string `json:"connectionType"`
	Action             string `json:"action"`
	Mode               string `json:"mode"`
	Address            string `json:"address,omitempty"`
	Username           string `json:"username,omitempty"`
	CredentialSecretID string `json:"credentialSecretId,omitempty"`
	HostPublicKey      string `json:"hostPublicKey,omitempty"`
}
