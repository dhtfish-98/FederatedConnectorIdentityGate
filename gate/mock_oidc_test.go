package gate_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type authorization struct {
	nonce       string
	redirectURI string
	created     time.Time
}

type localOIDC struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	redirectURI string
	clientID    string
	secret      string
	email       string
	subject     string
	mu          sync.Mutex
	verified    bool
	codes       map[string]authorization
}

func newLocalOIDC(t *testing.T, redirectURI, clientID, secret, subject, email string) *localOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &localOIDC{key: key, redirectURI: redirectURI, clientID: clientID, secret: secret, subject: subject, email: email, verified: true, codes: map[string]authorization{}}
	m.server = httptest.NewServer(http.HandlerFunc(m.serveHTTP))
	t.Cleanup(m.server.Close)
	return m
}

func (m *localOIDC) issuer() string { return m.server.URL }

func (m *localOIDC) setVerified(value bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verified = value
}

func (m *localOIDC) setSubject(value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subject = value
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func randomCode() (string, error) {
	raw := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (m *localOIDC) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, map[string]any{
			"issuer": m.issuer(), "authorization_endpoint": m.issuer() + "/auth",
			"token_endpoint": m.issuer() + "/token", "jwks_uri": m.issuer() + "/keys",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		})
	case "/keys":
		e := big.NewInt(int64(m.key.PublicKey.E)).Bytes()
		writeJSON(w, map[string]any{"keys": []any{map[string]string{
			"kty": "RSA", "kid": "local-rsa", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(m.key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	case "/auth":
		q := r.URL.Query()
		if r.Method != http.MethodGet || q.Get("response_type") != "code" || q.Get("client_id") != m.clientID ||
			q.Get("redirect_uri") != m.redirectURI || q.Get("state") == "" ||
			!strings.Contains(" "+q.Get("scope")+" ", " openid ") {
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		code, err := randomCode()
		if err != nil {
			http.Error(w, "code generation failed", http.StatusInternalServerError)
			return
		}
		m.mu.Lock()
		m.codes[code] = authorization{nonce: q.Get("nonce"), redirectURI: m.redirectURI, created: time.Now()}
		m.mu.Unlock()
		callback, _ := url.Parse(m.redirectURI)
		values := callback.Query()
		values.Set("code", code)
		values.Set("state", q.Get("state"))
		callback.RawQuery = values.Encode()
		http.Redirect(w, r, callback.String(), http.StatusFound)
	case "/token":
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "invalid token request", http.StatusBadRequest)
			return
		}
		user, password, basic := r.BasicAuth()
		if !basic {
			user, password = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		if user != m.clientID || password != m.secret {
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		m.mu.Lock()
		grant, ok := m.codes[r.Form.Get("code")]
		delete(m.codes, r.Form.Get("code"))
		verified := m.verified
		subject := m.subject
		m.mu.Unlock()
		if !ok || time.Since(grant.created) > time.Minute || grant.redirectURI != r.Form.Get("redirect_uri") {
			http.Error(w, "invalid code", http.StatusBadRequest)
			return
		}
		now := time.Now()
		token, err := m.sign(map[string]any{
			"iss": m.issuer(), "sub": subject, "aud": m.clientID,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": grant.nonce,
			"email": m.email, "email_verified": verified, "name": subject,
		})
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		access, err := randomCode()
		if err != nil {
			http.Error(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"access_token": access, "id_token": token, "token_type": "Bearer", "expires_in": 300})
	default:
		http.NotFound(w, r)
	}
}

func (m *localOIDC) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "local-rsa", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
