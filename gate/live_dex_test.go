package gate_test

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dhtfish-98/FederatedConnectorIdentityGate/gate"
)

const fixedDexCommit = "c7ced47db7f9dc92192969e6c396e393275278eb"

func sha(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func checkedDexBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("FCIG_DEX_BIN")
	if path == "" {
		t.Fatal("FCIG_DEX_BIN required for real Dex acceptance")
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	commitOK, clean := false, false
	for _, item := range info.Settings {
		if item.Key == "vcs.revision" && item.Value == fixedDexCommit {
			commitOK = true
		}
		if item.Key == "vcs.modified" && item.Value == "false" {
			clean = true
		}
	}
	if commitOK && clean {
		return path
	}
	t.Fatal("Dex executable does not carry a clean pinned upstream commit")
	return ""
}

// tokenExpiry is used only to wait for an already verified, Dex-signed token
// to expire in the live test. The application never trusts parsed JWT bytes.
func tokenExpiry(t *testing.T, raw string) time.Time {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("Dex token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Expires int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Expires <= 0 {
		t.Fatal("Dex token is missing an expiry")
	}
	return time.Unix(claims.Expires, 0)
}

func startDex(t *testing.T, dexBin, buildDir, issuer, callback, appSecret string, a, b *localOIDC) {
	t.Helper()
	upstreamSecret := a.secret
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`issuer: %s
storage:
  type: sqlite3
  config:
    file: %s
web:
  http: %s
oauth2:
  skipApprovalScreen: true
  grantTypes:
  - authorization_code
expiry:
  idTokens: "8s"
staticClients:
- id: identity-gate-lab
  redirectURIs:
  - '%s'
  name: Identity Gate Lab
  secret: %s
connectors:
- type: oidc
  id: source-a
  name: Source A
  config:
    issuer: %s
    clientID: dex-upstream
    clientSecret: %s
    redirectURI: %s/callback
- type: oidc
  id: source-b
  name: Source B
  config:
    issuer: %s
    clientID: dex-upstream
    clientSecret: %s
    redirectURI: %s/callback
enablePasswordDB: false
`, issuer, filepath.Join(buildDir, "dex.db"), issuerURL.Host, callback, appSecret, a.issuer(), upstreamSecret, issuer, b.issuer(), upstreamSecret, issuer)
	configPath := filepath.Join(buildDir, "dex.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(buildDir, "dex.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(dexBin, "serve", configPath)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = log.Close()
	})
	client := &http.Client{Timeout: time.Second}
	for attempt := 0; attempt < 100; attempt++ {
		response, err := client.Get(issuer + "/.well-known/openid-configuration")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("fixed Dex did not expose OIDC discovery; inspect Build/dex.log")
}

func dexIDToken(t *testing.T, issuer, callback, appSecret, connector, scope string) (string, string) {
	t.Helper()
	state, err := randomCode()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomCode()
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{
		"client_id": {"identity-gate-lab"}, "redirect_uri": {callback},
		"response_type": {"code"}, "scope": {scope},
		"state": {state}, "nonce": {nonce}, "connector_id": {connector},
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(request *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(request.URL.String(), callback+"?") {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	response, err := browser.Get(issuer + "/auth?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 500))
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther && response.StatusCode != http.StatusFound {
		t.Fatalf("authorization status %d at %s%s: %q", response.StatusCode, response.Request.URL.Host, response.Request.URL.Path, body)
	}
	final, err := url.Parse(response.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(final.String(), callback+"?") {
		t.Fatalf("unexpected callback: %v", err)
	}
	if final.Query().Get("state") != state || final.Query().Get("code") == "" {
		t.Fatal("state/code mismatch")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {final.Query().Get("code")}, "redirect_uri": {callback}}
	request, err := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("identity-gate-lab:"+appSecret)))
	response, err = (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 500))
		t.Fatalf("token exchange status %d: %s", response.StatusCode, body)
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil || tokens.IDToken == "" {
		t.Fatal("missing Dex ID token")
	}
	return tokens.IDToken, nonce
}

func TestLiveDexFederatedIsolation(t *testing.T) {
	dexBin := checkedDexBinary(t)
	buildDir := os.Getenv("FCIG_BUILD_DIR")
	if buildDir == "" {
		t.Fatal("FCIG_BUILD_DIR required for isolated artifacts")
	}
	runID, err := randomCode()
	if err != nil {
		t.Fatal(err)
	}
	buildDir = filepath.Join(buildDir, "run-"+runID)
	if err := os.MkdirAll(buildDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dexPort := freePort(t)
	callbackPort := freePort(t)
	issuer := fmt.Sprintf("http://127.0.0.1:%d/dex", dexPort)
	callback := fmt.Sprintf("http://127.0.0.1:%d/callback", callbackPort)
	upstreamSecret, err := randomCode()
	if err != nil {
		t.Fatal(err)
	}
	appSecret, err := randomCode()
	if err != nil {
		t.Fatal(err)
	}
	sharedEmail := "same-owner@example.invalid"
	a := newLocalOIDC(t, issuer+"/callback", "dex-upstream", upstreamSecret, "upstream-A-101", sharedEmail)
	b := newLocalOIDC(t, issuer+"/callback", "dex-upstream", upstreamSecret, "upstream-B-202", sharedEmail)
	startDex(t, dexBin, buildDir, issuer, callback, appSecret, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	rawA, nonceA := dexIDToken(t, issuer, callback, appSecret, "source-a", "openid email federated:id")
	rawB, nonceB := dexIDToken(t, issuer, callback, appSecret, "source-b", "openid email federated:id")
	identityA, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", nonceA, rawA)
	if err != nil {
		t.Fatalf("verify A: %v", err)
	}
	identityB, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", nonceB, rawB)
	if err != nil {
		t.Fatalf("verify B: %v", err)
	}
	if identityA.Email() != identityB.Email() || identityA.DexSubject() == identityB.DexSubject() ||
		identityA.UserID() == identityB.UserID() || identityA.ConnectorID() == identityB.ConnectorID() {
		t.Fatal("mock identity separation did not reach Dex")
	}
	// Deliberately weak baseline exists only in this test: email-only ownership collides.
	weakAccounts := map[string]string{strings.ToLower(identityA.Email()): "one-local-account"}
	weakA, weakB := weakAccounts[strings.ToLower(identityA.Email())], weakAccounts[strings.ToLower(identityB.Email())]
	weakResources := map[string]string{weakA: "alpha-owned-note"}
	if weakA != weakB || weakResources[weakB] != "alpha-owned-note" {
		t.Fatal("weak baseline did not demonstrate collision")
	}
	storePath := filepath.Join(buildDir, "app-state.json")
	store, err := gate.OpenStore(storePath, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessionA, subjectA, err := store.Bind(identityA, "")
	if err != nil {
		t.Fatal(err)
	}
	resourceA, err := store.CreateResource(sessionA, "alpha-owned-note")
	if err != nil {
		t.Fatal(err)
	}
	sessionB, subjectB, err := store.Bind(identityB, "")
	if err != nil {
		t.Fatal(err)
	}
	resourceB, err := store.CreateResource(sessionB, "beta-owned-note")
	if err != nil {
		t.Fatal(err)
	}
	if subjectA == subjectB {
		t.Fatal("guarded subjects merged")
	}
	if _, err := store.ReadResource(sessionA, resourceB); !errors.Is(err, gate.ErrDenied) {
		t.Fatal("A read B")
	}
	if _, err := store.ReadResource(sessionB, resourceA); !errors.Is(err, gate.ErrDenied) {
		t.Fatal("B read A")
	}
	if value, err := store.ReadResource(sessionA, resourceA); err != nil || value != "alpha-owned-note" {
		t.Fatal("A own read failed")
	}
	if value, err := store.ReadResource(sessionB, resourceB); err != nil || value != "beta-owned-note" {
		t.Fatal("B own read failed")
	}
	reopened, err := gate.OpenStore(storePath, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ReadResource(sessionB, resourceA); !errors.Is(err, gate.ErrDenied) {
		t.Fatal("reopened store merged owners")
	}
	newB, againB, err := reopened.Bind(identityB, sessionA)
	if err != nil || againB != subjectB {
		t.Fatal("connector switch changed B owner")
	}
	if _, err := reopened.ReadResource(sessionA, resourceA); !errors.Is(err, gate.ErrDenied) {
		t.Fatal("old A session replay survived rotation")
	}
	if _, err := reopened.ReadResource(newB, resourceA); !errors.Is(err, gate.ErrDenied) {
		t.Fatal("B after rotation read A")
	}
	b.setSubject(identityA.UserID())
	rawSameUserB, nonceSameUserB := dexIDToken(t, issuer, callback, appSecret, "source-b", "openid email federated:id")
	sameUserB, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", nonceSameUserB, rawSameUserB)
	if err != nil || sameUserB.UserID() != identityA.UserID() {
		t.Fatal("same-user connector control failed")
	}
	_, subjectSameUserB, err := reopened.Bind(sameUserB, "")
	if err != nil || subjectSameUserB == subjectA || subjectSameUserB == subjectB {
		t.Fatal("connector switch merged subjects")
	}
	if _, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", "wrong-nonce", rawA); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("wrong nonce accepted")
	}
	if _, err := gate.VerifyDexIDToken(ctx, client, issuer, "wrong-client", nonceA, rawA); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("wrong audience accepted")
	}
	if _, err := gate.VerifyDexIDToken(ctx, client, issuer+"/wrong-issuer", "identity-gate-lab", nonceA, rawA); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("wrong trusted issuer accepted")
	}
	parts := strings.Split(rawA, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	if _, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", nonceA, strings.Join(parts, ".")); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("altered signature accepted")
	}
	rawNoFederated, nonceNoFederated := dexIDToken(t, issuer, callback, appSecret, "source-a", "openid email")
	if _, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", nonceNoFederated, rawNoFederated); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("token without federated identifiers accepted")
	}
	b.setVerified(false)
	rawUnverified, nonceUnverified := dexIDToken(t, issuer, callback, appSecret, "source-b", "openid email federated:id")
	if _, err := gate.VerifyDexIDToken(ctx, client, issuer, "identity-gate-lab", nonceUnverified, rawUnverified); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("unverified email accepted")
	}
	expires := tokenExpiry(t, rawA)
	if wait := time.Until(expires.Add(2 * time.Second)); wait > 0 {
		time.Sleep(wait)
	}
	// The exact same real, previously accepted Dex-signed token is now expired.
	if _, err := gate.VerifyDexIDToken(context.Background(), client, issuer, "identity-gate-lab", nonceA, rawA); !errors.Is(err, gate.ErrUnverified) {
		t.Fatal("expired Dex token accepted")
	}
	if path := os.Getenv("FCIG_EVIDENCE_PATH"); path != "" {
		binary, err := os.ReadFile(dexBin)
		if err != nil {
			t.Fatal(err)
		}
		dexHash := sha256.Sum256(binary)
		evidence := map[string]any{
			"schema": 1, "dex_commit": fixedDexCommit, "dex_binary_sha256": hex.EncodeToString(dexHash[:]),
			"source_a":                  map[string]any{"connector_id": identityA.ConnectorID(), "upstream_user_id": identityA.UserID(), "dex_subject_sha256": sha(identityA.DexSubject()), "email_sha256": sha(identityA.Email()), "token_sha256": sha(rawA)},
			"source_b":                  map[string]any{"connector_id": identityB.ConnectorID(), "upstream_user_id": identityB.UserID(), "dex_subject_sha256": sha(identityB.DexSubject()), "email_sha256": sha(identityB.Email()), "token_sha256": sha(rawB)},
			"weak_email_only_collision": true, "guarded_distinct_subjects": true, "resource_cross_reads_denied": true,
			"persistent_store_reopened": true, "old_session_replay_denied_after_rotation": true,
			"same_user_id_different_connector_separated": true,
			"wrong_nonce_denied":                         true, "wrong_audience_denied": true, "altered_signature_denied": true,
			"wrong_trusted_issuer_denied": true, "expired_dex_token_denied": true,
			"missing_federated_claims_denied": true, "unverified_email_denied": true,
		}
		bytes, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(bytes, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
