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
	SessionID      string `json:"sessionId"`
	UserID         string `json:"userId,omitempty"`
	HostID         string `json:"hostId,omitempty"`
	CRID           string `json:"crId,omitempty"`
	ConnectionType string `json:"connectionType,omitempty"`
	Action         string `json:"action,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Token          string `json:"token"`
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

type AutomationTokenRequest struct {
	RunID             string   `json:"runId"`
	IncidentID        string   `json:"incidentId"`
	HostID            string   `json:"hostId"`
	Phase             string   `json:"phase"`
	AllowedOperations []string `json:"allowedOperations"`
	PlanHash          string   `json:"planHash,omitempty"`
	OwnerPodID        string   `json:"ownerPodId"`
	OwnerInstanceID   string   `json:"ownerInstanceId"`
}

type AutomationTokenResponse struct {
	TokenType       string    `json:"tokenType"`
	CapabilityToken string    `json:"capabilityToken"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type AutomationTokenValidateRequest struct {
	RunID string `json:"runId"`
	Token string `json:"token"`
}

type AutomationClaims struct {
	RunID              string   `json:"runId"`
	IncidentID         string   `json:"incidentId"`
	HostID             string   `json:"hostId"`
	CatalogVersion     string   `json:"catalogVersion,omitempty"`
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
}

type AutomationValidateResponse struct {
	Allowed bool              `json:"allowed"`
	Reason  string            `json:"reason,omitempty"`
	Claims  *AutomationClaims `json:"claims,omitempty"`
}
