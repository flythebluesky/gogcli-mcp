package mcpauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetadataEndpoint(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, key := range []string{"issuer", "authorization_endpoint", "token_endpoint"} {
		if _, ok := meta[key]; !ok {
			t.Errorf("missing metadata field: %s", key)
		}
	}

	if meta["code_challenge_methods_supported"] == nil {
		t.Error("missing code_challenge_methods_supported")
	}
	if meta["registration_endpoint"] != nil {
		t.Error("should not advertise registration_endpoint")
	}
}

func registerTestClient(store *Store, id, secret, name string, uris []string) {
	store.mu.Lock()
	store.clients[id] = &Client{ID: id, Secret: secret, Name: name, RedirectURIs: uris}
	store.mu.Unlock()
}

func TestAuthorizeRendersConsentPage(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")
	registerTestClient(store, "test-client", "test-secret", "Test Client", []string{"https://example.com/callback"})

	req := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=abc123&code_challenge_method=S256&state=xyz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	b := w.Body.String()
	if !strings.Contains(b, "Test Client") {
		t.Error("consent page should show client name")
	}
	if !strings.Contains(b, "Approve") {
		t.Error("consent page should have Approve button")
	}
}

func TestAuthorizePostRedirectsWithCode(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")
	registerTestClient(store, "test-client", "test-secret", "Test Client", []string{"https://example.com/callback"})

	form := "client_id=test-client&redirect_uri=https://example.com/callback&code_challenge=abc123&code_challenge_method=S256&state=xyz"
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://example.com/callback") {
		t.Fatalf("unexpected redirect: %s", loc)
	}
	if !strings.Contains(loc, "code=") {
		t.Error("redirect should contain authorization code")
	}
	if !strings.Contains(loc, "state=xyz") {
		t.Error("redirect should preserve state")
	}
}

func TestTokenExchangeWithPKCE(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")

	codeVerifier := "test-verifier-that-is-long-enough-for-pkce-spec"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	registerTestClient(store, "c1", "s1", "Test", []string{"https://example.com/cb"})
	store.mu.Lock()
	store.codes["authcode1"] = &authCode{
		code: "authcode1", clientID: "c1",
		redirectURI: "https://example.com/cb",
		codeChallenge: codeChallenge, codeChallengeMethod: "S256",
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	store.mu.Unlock()

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"authcode1"},
		"redirect_uri": {"https://example.com/cb"}, "client_id": {"c1"},
		"client_secret": {"s1"}, "code_verifier": {codeVerifier},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("missing access_token")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("missing refresh_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", resp["token_type"])
	}
}

func TestTokenExchangeRejectsBadVerifier(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")

	h := sha256.Sum256([]byte("correct-verifier"))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	registerTestClient(store, "c1", "s1", "Test", []string{"https://example.com/cb"})
	store.mu.Lock()
	store.codes["authcode2"] = &authCode{
		code: "authcode2", clientID: "c1",
		redirectURI: "https://example.com/cb",
		codeChallenge: codeChallenge, codeChallengeMethod: "S256",
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	store.mu.Unlock()

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"authcode2"},
		"redirect_uri": {"https://example.com/cb"}, "client_id": {"c1"},
		"client_secret": {"s1"}, "code_verifier": {"wrong-verifier"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")

	codeVerifier := "test-verifier-that-is-long-enough-for-pkce-spec"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	registerTestClient(store, "c1", "s1", "Test", []string{"https://example.com/cb"})
	store.mu.Lock()
	store.codes["code1"] = &authCode{
		code: "code1", clientID: "c1",
		redirectURI: "https://example.com/cb",
		codeChallenge: codeChallenge, codeChallengeMethod: "S256",
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	store.mu.Unlock()

	// Exchange auth code for tokens.
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"code1"},
		"redirect_uri": {"https://example.com/cb"}, "client_id": {"c1"},
		"client_secret": {"s1"}, "code_verifier": {codeVerifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var first map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &first)
	refreshToken := first["refresh_token"].(string)

	// Use refresh token to get new tokens.
	form = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	}
	req = httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var second map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &second)

	if second["access_token"] == nil || second["access_token"] == "" {
		t.Error("missing access_token from refresh")
	}
	if second["refresh_token"] == nil || second["refresh_token"] == "" {
		t.Error("missing new refresh_token from refresh")
	}
	if second["access_token"] == first["access_token"] {
		t.Error("refresh should issue a new access token")
	}
	if second["refresh_token"] == first["refresh_token"] {
		t.Error("refresh should rotate the refresh token")
	}

	// Old refresh token should be consumed (replay rejected).
	form = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"c1"},
		"client_secret": {"s1"},
	}
	req = httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for replayed refresh token, got %d", w.Code)
	}
}

func TestMiddleware(t *testing.T) {
	store := NewStore("")

	store.mu.Lock()
	store.tokens["good-token"] = &Token{
		Value: "good-token", ClientID: "c1",
		Expires: time.Now().Add(1 * time.Hour),
	}
	store.mu.Unlock()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(store, "https://example.com", inner)

	req := httptest.NewRequest("POST", "/mcp", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "resource_metadata=") {
		t.Errorf("expected resource_metadata in WWW-Authenticate, got %q", wwwAuth)
	}

	req = httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("expected invalid_token in WWW-Authenticate, got %q", w.Header().Get("WWW-Authenticate"))
	}

	req = httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestValidateToken(t *testing.T) {
	store := NewStore("")

	store.mu.Lock()
	store.tokens["valid-token"] = &Token{
		Value: "valid-token", ClientID: "c1",
		Expires: time.Now().Add(1 * time.Hour),
	}
	store.tokens["expired-token"] = &Token{
		Value: "expired-token", ClientID: "c1",
		Expires: time.Now().Add(-1 * time.Hour),
	}
	store.mu.Unlock()

	if !store.ValidateToken("valid-token") {
		t.Error("expected valid token to pass")
	}
	if store.ValidateToken("expired-token") {
		t.Error("expected expired token to fail")
	}
	if store.ValidateToken("nonexistent") {
		t.Error("expected unknown token to fail")
	}
}

func TestTokenExchangeWithBasicAuth(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")

	codeVerifier := "test-verifier-that-is-long-enough-for-pkce-spec"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	registerTestClient(store, "c1", "s1", "Test", []string{"https://example.com/cb"})
	store.mu.Lock()
	store.codes["basiccode"] = &authCode{
		code: "basiccode", clientID: "c1",
		redirectURI: "https://example.com/cb",
		codeChallenge: codeChallenge, codeChallengeMethod: "S256",
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	store.mu.Unlock()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"basiccode"},
		"redirect_uri":  {"https://example.com/cb"},
		"code_verifier": {codeVerifier},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("c1", "s1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("missing access_token")
	}
}

func TestRefreshTokenWithBasicAuth(t *testing.T) {
	store := NewStore("")
	handler := NewHandler(store, "https://example.com")

	registerTestClient(store, "c1", "s1", "Test", []string{"https://example.com/cb"})
	store.mu.Lock()
	store.refreshTokens["rt1"] = &RefreshToken{
		Value: "rt1", ClientID: "c1",
		Expires: time.Now().Add(1 * time.Hour),
	}
	store.mu.Unlock()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"rt1"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("c1", "s1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegisterClient(t *testing.T) {
	store := NewStore("")

	client := store.RegisterClient("Claude", []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://claude.com/api/mcp/auth_callback",
	})

	if client.ID == "" || client.Secret == "" {
		t.Error("expected non-empty client ID and secret")
	}
	if client.Name != "Claude" {
		t.Errorf("expected name Claude, got %s", client.Name)
	}
	if len(client.RedirectURIs) != 2 {
		t.Errorf("expected 2 redirect URIs, got %d", len(client.RedirectURIs))
	}

	if !store.ValidateClient(client.ID, client.Secret) {
		t.Error("registered client should be valid")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oauth.json")

	// Create store, register client, issue token.
	s1 := NewStore(path)
	s1.mu.Lock()
	s1.clients["c1"] = &Client{ID: "c1", Secret: "s1", Name: "Test", RedirectURIs: []string{"https://example.com/cb"}}
	s1.tokens["tok1"] = &Token{Value: "tok1", ClientID: "c1", Expires: time.Now().Add(1 * time.Hour)}
	s1.tokens["expired"] = &Token{Value: "expired", ClientID: "c1", Expires: time.Now().Add(-1 * time.Hour)}
	s1.save()
	s1.mu.Unlock()

	// Load into new store — should have client and valid token, not expired one.
	s2 := NewStore(path)
	if !s2.ValidateToken("tok1") {
		t.Error("expected persisted token to be valid")
	}
	if s2.ValidateToken("expired") {
		t.Error("expected expired token to be pruned on load")
	}

	s2.mu.Lock()
	c, ok := s2.clients["c1"]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("expected persisted client")
	}
	if c.Name != "Test" {
		t.Errorf("expected client name Test, got %s", c.Name)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected state file to exist: %v", err)
	}
}
