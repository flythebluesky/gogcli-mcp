// Package mcpauth implements OAuth 2.1 authorization for MCP servers,
// per the MCP authorization spec (2025-03-26).
package mcpauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Client is a dynamically registered OAuth client.
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// Token is an issued access token.
type Token struct {
	Value    string    `json:"value"`
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
}

// RefreshToken is a long-lived token used to obtain new access tokens.
type RefreshToken struct {
	Value    string    `json:"value"`
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
}

type authCode struct {
	code                string
	clientID            string
	redirectURI         string
	codeChallenge       string
	codeChallengeMethod string
	expiresAt           time.Time
}

// storeData is the JSON-serializable snapshot of persistent state.
type storeData struct {
	Clients       map[string]*Client       `json:"clients"`
	Tokens        map[string]*Token        `json:"tokens"`
	RefreshTokens map[string]*RefreshToken `json:"refresh_tokens,omitempty"`
}

// Store holds OAuth state with optional file persistence.
type Store struct {
	mu            sync.Mutex
	clients       map[string]*Client
	codes         map[string]*authCode // ephemeral, not persisted
	tokens        map[string]*Token
	refreshTokens map[string]*RefreshToken
	path          string // empty = no persistence
}

// NewStore creates an OAuth store. If path is non-empty, state is loaded
// from and saved to that file. Expired tokens are pruned on load.
func NewStore(path string) *Store {
	s := &Store{
		clients:       make(map[string]*Client),
		codes:         make(map[string]*authCode),
		tokens:        make(map[string]*Token),
		refreshTokens: make(map[string]*RefreshToken),
		path:          path,
	}
	if path != "" {
		s.load()
	}
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return // file doesn't exist yet
	}
	var snap storeData
	if err := json.Unmarshal(data, &snap); err != nil {
		return
	}
	now := time.Now()
	if snap.Clients != nil {
		s.clients = snap.Clients
	}
	if snap.Tokens != nil {
		for k, t := range snap.Tokens {
			if now.Before(t.Expires) {
				s.tokens[k] = t
			}
		}
	}
	if snap.RefreshTokens != nil {
		for k, rt := range snap.RefreshTokens {
			if now.Before(rt.Expires) {
				s.refreshTokens[k] = rt
			}
		}
	}
}

func (s *Store) save() {
	if s.path == "" {
		return
	}
	snap := storeData{
		Clients:       s.clients,
		Tokens:        s.tokens,
		RefreshTokens: s.refreshTokens,
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(s.path), 0700)
	os.WriteFile(s.path, data, 0600)
}

// ValidateToken checks whether a bearer token is valid and not expired.
func (s *Store) ValidateToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[token]
	if !ok {
		return false
	}
	if time.Now().After(t.Expires) {
		delete(s.tokens, token)
		s.save()
		return false
	}
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// Handler serves all OAuth endpoints (metadata, register, authorize, token).
type Handler struct {
	store               *Store
	issuer              string
	accessTokenTTL      time.Duration
	refreshTokenTTL     time.Duration
	resourceDescription string
	mux                 *http.ServeMux
}

// Option configures a Handler.
type Option func(*Handler)

// WithAccessTokenTTL sets the access token lifetime. Default is 1 hour.
func WithAccessTokenTTL(d time.Duration) Option {
	return func(h *Handler) { h.accessTokenTTL = d }
}

// WithRefreshTokenTTL sets the refresh token lifetime. Default is 365 days.
func WithRefreshTokenTTL(d time.Duration) Option {
	return func(h *Handler) { h.refreshTokenTTL = d }
}

// WithResourceDescription sets the text shown on the consent page describing
// what the client wants to access. Default is "this server's tools".
func WithResourceDescription(desc string) Option {
	return func(h *Handler) { h.resourceDescription = desc }
}

// NewHandler creates an OAuth handler with all routes registered.
func NewHandler(store *Store, issuer string, opts ...Option) *Handler {
	h := &Handler{store: store, issuer: issuer, accessTokenTTL: 1 * time.Hour, refreshTokenTTL: 365 * 24 * time.Hour, resourceDescription: "this server's tools"}
	for _, o := range opts {
		o(h)
	}
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.handleMetadata)
	h.mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)
	h.mux.HandleFunc("GET /authorize", h.handleAuthorizeGet)
	h.mux.HandleFunc("POST /authorize", h.handleAuthorizePost)
	h.mux.HandleFunc("POST /token", h.handleToken)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// Middleware returns an http.Handler that validates Bearer tokens
// before passing requests to next. The issuer is used to construct
// the resource_metadata URL in the WWW-Authenticate header.
func Middleware(store *Store, issuer string, next http.Handler) http.Handler {
	resourceMeta := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, issuer)
	resourceMetaInvalid := fmt.Sprintf(`Bearer error="invalid_token", resource_metadata="%s/.well-known/oauth-protected-resource"`, issuer)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", resourceMeta)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if !store.ValidateToken(token) {
			w.Header().Set("WWW-Authenticate", resourceMetaInvalid)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	meta := map[string]interface{}{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/authorize",
		"token_endpoint":                        h.issuer + "/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func (h *Handler) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	meta := map[string]interface{}{
		"resource":              h.issuer,
		"authorization_servers": []string{h.issuer},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

var consentTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html><head><title>Authorize</title>
<style>body{font-family:system-ui;max-width:400px;margin:80px auto;text-align:center}
button{padding:12px 32px;font-size:16px;cursor:pointer;border:none;border-radius:6px;margin:8px}
.approve{background:#2563eb;color:#fff}.deny{background:#e5e7eb}</style></head>
<body><h2>Authorize Access</h2>
<p><strong>{{.ClientName}}</strong> wants to access {{.ResourceDescription}}.</p>
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
<input type="hidden" name="state" value="{{.State}}">
<button type="submit" class="approve">Approve</button>
</form>
<form method="GET" action="{{.RedirectURI}}">
<input type="hidden" name="error" value="access_denied">
<input type="hidden" name="state" value="{{.State}}">
<button type="submit" class="deny">Deny</button>
</form></body></html>`))

func (h *Handler) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	state := r.URL.Query().Get("state")

	if codeChallengeMethod != "S256" || codeChallenge == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"PKCE S256 required"}`, http.StatusBadRequest)
		return
	}

	h.store.mu.Lock()
	client, ok := h.store.clients[clientID]
	h.store.mu.Unlock()

	if !ok {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}
	if !validRedirectURI(client, redirectURI) {
		http.Error(w, `{"error":"invalid_redirect_uri"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	consentTmpl.Execute(w, map[string]string{
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"State":               state,
		"ResourceDescription": h.resourceDescription,
	})
}

func (h *Handler) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	state := r.FormValue("state")

	if codeChallengeMethod != "S256" || codeChallenge == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"PKCE S256 required"}`, http.StatusBadRequest)
		return
	}

	h.store.mu.Lock()
	client, ok := h.store.clients[clientID]
	h.store.mu.Unlock()

	if !ok {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}
	if !validRedirectURI(client, redirectURI) {
		http.Error(w, `{"error":"invalid_redirect_uri"}`, http.StatusBadRequest)
		return
	}

	code := &authCode{
		code:                randomHex(32),
		clientID:            clientID,
		redirectURI:         redirectURI,
		codeChallenge:       codeChallenge,
		codeChallengeMethod: codeChallengeMethod,
		expiresAt:           time.Now().Add(10 * time.Minute),
	}

	h.store.mu.Lock()
	h.store.codes[code.code] = code
	h.store.mu.Unlock()

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code.code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func validRedirectURI(client *Client, uri string) bool {
	for _, u := range client.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	switch r.FormValue("grant_type") {
	case "authorization_code":
		h.handleTokenAuthCode(w, r)
	case "refresh_token":
		h.handleTokenRefresh(w, r)
	default:
		jsonError(w, "unsupported_grant_type", "", http.StatusBadRequest)
	}
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func (h *Handler) handleTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret := extractClientCredentials(r)
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	h.store.mu.Lock()
	ac, codeOK := h.store.codes[code]
	client, clientOK := h.store.clients[clientID]
	if codeOK {
		delete(h.store.codes, code)
	}
	h.store.mu.Unlock()

	if !clientOK || subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		jsonError(w, "invalid_client", "", http.StatusBadRequest)
		return
	}
	if !codeOK || ac.clientID != clientID || ac.redirectURI != redirectURI {
		jsonError(w, "invalid_grant", "", http.StatusBadRequest)
		return
	}
	if time.Now().After(ac.expiresAt) {
		jsonError(w, "invalid_grant", "code expired", http.StatusBadRequest)
		return
	}

	if codeVerifier == "" {
		jsonError(w, "invalid_grant", "code_verifier required", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != ac.codeChallenge {
		jsonError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
		return
	}

	h.issueTokens(w, clientID)
}

func (h *Handler) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret := extractClientCredentials(r)
	refreshValue := r.FormValue("refresh_token")

	h.store.mu.Lock()
	client, clientOK := h.store.clients[clientID]
	rt, rtOK := h.store.refreshTokens[refreshValue]

	// Validate everything before consuming the refresh token.
	valid := clientOK && rtOK &&
		subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) == 1 &&
		rt.ClientID == clientID &&
		time.Now().Before(rt.Expires)

	if valid {
		delete(h.store.refreshTokens, refreshValue)
	}
	h.store.mu.Unlock()

	if !valid {
		if !clientOK {
			jsonError(w, "invalid_client", "", http.StatusBadRequest)
		} else {
			jsonError(w, "invalid_grant", "", http.StatusBadRequest)
		}
		return
	}

	h.issueTokens(w, clientID)
}

func (h *Handler) issueTokens(w http.ResponseWriter, clientID string) {
	tok := &Token{
		Value:    randomHex(32),
		ClientID: clientID,
		Expires:  time.Now().Add(h.accessTokenTTL),
	}
	rt := &RefreshToken{
		Value:    randomHex(32),
		ClientID: clientID,
		Expires:  time.Now().Add(h.refreshTokenTTL),
	}

	h.store.mu.Lock()
	h.store.tokens[tok.Value] = tok
	h.store.refreshTokens[rt.Value] = rt
	h.store.save()
	h.store.mu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  tok.Value,
		"refresh_token": rt.Value,
		"token_type":    "Bearer",
		"expires_in":    int(h.accessTokenTTL / time.Second),
	})
}

func (s *Store) RegisterClient(name string, redirectURIs []string) *Client {
	client := &Client{
		ID:           randomHex(16),
		Secret:       randomHex(32),
		Name:         name,
		RedirectURIs: redirectURIs,
	}
	s.mu.Lock()
	s.clients[client.ID] = client
	s.save()
	s.mu.Unlock()
	return client
}

// EnsureClient registers a client with a specific ID and secret if it doesn't
// already exist. If a client with the same ID exists, it is left unchanged.
func (s *Store) EnsureClient(id, secret, name string, redirectURIs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; ok {
		return
	}
	s.clients[id] = &Client{
		ID:           id,
		Secret:       secret,
		Name:         name,
		RedirectURIs: redirectURIs,
	}
	s.save()
}

func (s *Store) ValidateClient(id, secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	return ok && subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) == 1
}

func (s *Store) GetClients() []*Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients := make([]*Client, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	return clients
}

func jsonError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]string{"error": errCode}
	if description != "" {
		resp["error_description"] = description
	}
	json.NewEncoder(w).Encode(resp)
}
