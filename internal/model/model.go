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
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type SessionTokenRequest struct {
	SessionID string `json:"sessionId"`
	UserID    string `json:"userId"`
	Mode      string `json:"mode"`
}

type SessionTokenResponse struct {
	SessionToken string    `json:"sessionToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type TokenValidateRequest struct {
	SessionID string `json:"sessionId"`
	UserID    string `json:"userId,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Token     string `json:"token"`
}
