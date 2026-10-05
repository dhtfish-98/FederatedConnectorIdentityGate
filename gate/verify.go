package gate

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var ErrUnverified = errors.New("unverified_identity")

// VerifiedIdentity can only be populated by VerifyDexIDToken. Its zero value is invalid.
type VerifiedIdentity struct {
	issuer      string
	dexSubject  string
	connectorID string
	userID      string
	email       string
	verified    bool
}

func (v VerifiedIdentity) Issuer() string      { return v.issuer }
func (v VerifiedIdentity) DexSubject() string  { return v.dexSubject }
func (v VerifiedIdentity) ConnectorID() string { return v.connectorID }
func (v VerifiedIdentity) UserID() string      { return v.userID }
func (v VerifiedIdentity) Email() string       { return v.email }

// VerifyDexIDToken verifies a real Dex ID token against a configured issuer and
// client. The nonce must come from the corresponding authorization request.
// Email is retained only as display metadata; it is never an account key.
func VerifyDexIDToken(ctx context.Context, client *http.Client, issuer, clientID, nonce, raw string) (VerifiedIdentity, error) {
	if client == nil || issuer == "" || clientID == "" || nonce == "" || raw == "" {
		return VerifiedIdentity{}, ErrUnverified
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return VerifiedIdentity{}, ErrUnverified
	}
	token, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, raw)
	if err != nil {
		return VerifiedIdentity{}, ErrUnverified
	}
	var claims struct {
		Nonce         string `json:"nonce"`
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Federated     *struct {
			ConnectorID string `json:"connector_id"`
			UserID      string `json:"user_id"`
		} `json:"federated_claims"`
	}
	if err := token.Claims(&claims); err != nil || claims.Nonce != nonce ||
		claims.EmailVerified == nil || !*claims.EmailVerified ||
		claims.Federated == nil || strings.TrimSpace(claims.Federated.ConnectorID) == "" ||
		strings.TrimSpace(claims.Federated.UserID) == "" || token.Subject == "" ||
		len(claims.Federated.ConnectorID) > 256 || len(claims.Federated.UserID) > 256 ||
		len(claims.Email) > 320 || strings.TrimSpace(claims.Email) == "" ||
		token.Expiry.Before(time.Now()) {
		return VerifiedIdentity{}, ErrUnverified
	}
	return VerifiedIdentity{
		issuer: issuer, dexSubject: token.Subject,
		connectorID: claims.Federated.ConnectorID, userID: claims.Federated.UserID,
		email: claims.Email, verified: true,
	}, nil
}
