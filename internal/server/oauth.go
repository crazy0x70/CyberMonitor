package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	adminOAuthStateCookieName = "cm_admin_oauth_state"
	adminOAuthStateTTL        = 10 * time.Minute
	adminOAuthHTTPTimeout     = 8 * time.Second
	adminOAuthProviderGitHub  = "github"
	adminOAuthProviderOIDC    = "oidc"
)

type adminOAuthStatePayload struct {
	Provider     string `json:"provider"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	Nonce        string `json:"nonce,omitempty"`
	ReturnTo     string `json:"return_to"`
	ExpiresAt    int64  `json:"expires_at"`
}

type adminOAuthIdentity struct {
	Subject       string
	Login         string
	Email         string
	EmailVerified bool
}

type adminOAuthLoginProvider struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
}

func defaultAdminAuthSettings() AdminAuthSettings {
	settings := AdminAuthSettings{PasswordLoginEnabled: true}
	return normalizeAdminAuthSettings(settings)
}

func mergeAdminAuthSettings(existing, fallback AdminAuthSettings) AdminAuthSettings {
	existing = normalizeAdminAuthSettings(existing)
	fallback = normalizeAdminAuthSettings(fallback)
	if !existing.PasswordLoginEnabled && !adminAuthProviderConfigured(existing) && fallback.PasswordLoginEnabled {
		existing.PasswordLoginEnabled = true
	}
	return existing
}

func cloneAdminAuthSettings(settings AdminAuthSettings) AdminAuthSettings {
	settings.GitHub.Scopes = cloneStringSlice(settings.GitHub.Scopes)
	settings.GitHub.AllowedLogins = cloneStringSlice(settings.GitHub.AllowedLogins)
	settings.GitHub.AllowedEmails = cloneStringSlice(settings.GitHub.AllowedEmails)
	settings.GitHub.AllowedEmailDomains = cloneStringSlice(settings.GitHub.AllowedEmailDomains)
	settings.OIDC.Scopes = cloneStringSlice(settings.OIDC.Scopes)
	settings.OIDC.AllowedSubjects = cloneStringSlice(settings.OIDC.AllowedSubjects)
	settings.OIDC.AllowedEmails = cloneStringSlice(settings.OIDC.AllowedEmails)
	settings.OIDC.AllowedEmailDomains = cloneStringSlice(settings.OIDC.AllowedEmailDomains)
	return settings
}

func normalizeAdminAuthSettings(settings AdminAuthSettings) AdminAuthSettings {
	settings = cloneAdminAuthSettings(settings)
	settings.GitHub.DisplayName = strings.TrimSpace(settings.GitHub.DisplayName)
	if settings.GitHub.DisplayName == "" {
		settings.GitHub.DisplayName = "GitHub"
	}
	settings.GitHub.ClientID = strings.TrimSpace(settings.GitHub.ClientID)
	settings.GitHub.ClientSecret = strings.TrimSpace(settings.GitHub.ClientSecret)
	settings.GitHub.Scopes = normalizeStringList(settings.GitHub.Scopes, []string{"read:user", "user:email"}, false)
	settings.GitHub.AllowedLogins = normalizeStringList(settings.GitHub.AllowedLogins, nil, true)
	settings.GitHub.AllowedEmails = normalizeEmailList(settings.GitHub.AllowedEmails)
	settings.GitHub.AllowedEmailDomains = normalizeDomainList(settings.GitHub.AllowedEmailDomains)

	settings.OIDC.DisplayName = strings.TrimSpace(settings.OIDC.DisplayName)
	if settings.OIDC.DisplayName == "" {
		settings.OIDC.DisplayName = "OpenID Connect"
	}
	settings.OIDC.IssuerURL = strings.TrimRight(strings.TrimSpace(settings.OIDC.IssuerURL), "/")
	settings.OIDC.ClientID = strings.TrimSpace(settings.OIDC.ClientID)
	settings.OIDC.ClientSecret = strings.TrimSpace(settings.OIDC.ClientSecret)
	settings.OIDC.Scopes = normalizeStringList(settings.OIDC.Scopes, []string{"openid", "email", "profile"}, false)
	settings.OIDC.AllowedSubjects = normalizeStringList(settings.OIDC.AllowedSubjects, nil, false)
	settings.OIDC.AllowedEmails = normalizeEmailList(settings.OIDC.AllowedEmails)
	settings.OIDC.AllowedEmailDomains = normalizeDomainList(settings.OIDC.AllowedEmailDomains)

	if !settings.PasswordLoginEnabled && !adminAuthProviderConfigured(settings) {
		settings.PasswordLoginEnabled = true
	}
	return settings
}

func redactAdminAuthSettings(settings AdminAuthSettings) AdminAuthSettings {
	settings = normalizeAdminAuthSettings(settings)
	settings.GitHub.ClientSecret = ""
	settings.OIDC.ClientSecret = ""
	return settings
}

func preserveAdminAuthSecrets(next, existing AdminAuthSettings) AdminAuthSettings {
	next = normalizeAdminAuthSettings(next)
	existing = normalizeAdminAuthSettings(existing)
	if strings.TrimSpace(next.GitHub.ClientSecret) == "" {
		next.GitHub.ClientSecret = strings.TrimSpace(existing.GitHub.ClientSecret)
	}
	if strings.TrimSpace(next.OIDC.ClientSecret) == "" {
		next.OIDC.ClientSecret = strings.TrimSpace(existing.OIDC.ClientSecret)
	}
	return next
}

func validateAdminAuthSettings(settings AdminAuthSettings) error {
	settings = normalizeAdminAuthSettings(settings)
	if settings.GitHub.Enabled {
		if settings.GitHub.ClientID == "" || settings.GitHub.ClientSecret == "" {
			return errors.New("github oauth client id and secret required")
		}
		if !oauth2AllowListConfigured(settings.GitHub.AllowedLogins, settings.GitHub.AllowedEmails, settings.GitHub.AllowedEmailDomains) {
			return errors.New("github oauth allowlist required")
		}
	}
	if settings.OIDC.Enabled {
		if err := validateOIDCIssuerURL(settings.OIDC.IssuerURL); err != nil {
			return err
		}
		if settings.OIDC.ClientID == "" || settings.OIDC.ClientSecret == "" {
			return errors.New("oidc client id and secret required")
		}
		if !oauth2AllowListConfigured(settings.OIDC.AllowedSubjects, settings.OIDC.AllowedEmails, settings.OIDC.AllowedEmailDomains) {
			return errors.New("oidc allowlist required")
		}
	}
	if !settings.PasswordLoginEnabled && !adminAuthProviderConfigured(settings) {
		return errors.New("password login can only be disabled after enabling an oauth or oidc provider")
	}
	return nil
}

func adminAuthSettingsEqual(a, b AdminAuthSettings) bool {
	return reflect.DeepEqual(normalizeAdminAuthSettings(a), normalizeAdminAuthSettings(b))
}

func adminAuthProviderConfigured(settings AdminAuthSettings) bool {
	return settings.GitHub.Enabled || settings.OIDC.Enabled
}

func oauth2AllowListConfigured(primary, emails, domains []string) bool {
	return len(primary) > 0 || len(emails) > 0 || len(domains) > 0
}

func normalizeStringList(values []string, fallback []string, lower bool) []string {
	if len(values) == 0 && len(fallback) > 0 {
		values = fallback
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if lower {
			item = strings.ToLower(item)
		}
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func normalizeEmailList(values []string) []string {
	return normalizeStringList(values, nil, true)
}

func normalizeDomainList(values []string) []string {
	result := normalizeStringList(values, nil, true)
	for i := range result {
		result[i] = strings.TrimPrefix(result[i], "@")
	}
	return slices.DeleteFunc(result, func(value string) bool {
		return value == "" || strings.ContainsAny(value, " /\\")
	})
}

func validateOIDCIssuerURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("oidc issuer_url must be an https origin or path without query or fragment")
	}
	return nil
}

func issueAdminSession(w http.ResponseWriter, r *http.Request, secret string, store *Store, trustedProxyHeaders bool) (int64, error) {
	if store == nil {
		return 0, errors.New("store required")
	}
	creds := store.Credentials()
	token, exp, err := generateToken(secret, creds.AdminUser, creds.TokenSalt)
	if err != nil {
		return 0, err
	}
	setAdminSessionCookie(w, r, token, exp, trustedProxyHeaders)
	return exp, nil
}

func buildAdminLoginConfig(store *Store) map[string]any {
	settings := normalizeAdminAuthSettings(store.Credentials().AdminAuth)
	providers := make([]adminOAuthLoginProvider, 0, 2)
	if githubOAuthReady(settings.GitHub) {
		providers = append(providers, adminOAuthLoginProvider{
			ID:          adminOAuthProviderGitHub,
			DisplayName: settings.GitHub.DisplayName,
			Type:        "oauth2",
		})
	}
	if oidcOAuthReady(settings.OIDC) {
		providers = append(providers, adminOAuthLoginProvider{
			ID:          adminOAuthProviderOIDC,
			DisplayName: settings.OIDC.DisplayName,
			Type:        "oidc",
		})
	}
	return map[string]any{
		"password_login_enabled": settings.PasswordLoginEnabled,
		"oauth_providers":        providers,
	}
}

func githubOAuthReady(settings OAuth2ProviderSettings) bool {
	return settings.Enabled && settings.ClientID != "" && settings.ClientSecret != ""
}

func oidcOAuthReady(settings OIDCProviderSettings) bool {
	return settings.Enabled && settings.IssuerURL != "" && settings.ClientID != "" && settings.ClientSecret != ""
}

func handleAdminOAuthStart(store *Store, jwtSecret string, trustedProxyHeaders bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		providerID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
		settings := normalizeAdminAuthSettings(store.Credentials().AdminAuth)
		redirectURI := adminOAuthRedirectURI(r, trustedProxyHeaders)
		oauthConfig, _, nonce, err := adminOAuthConfigForProvider(r.Context(), providerID, settings, redirectURI)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		state, err := randomToken(32)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "state error"})
			return
		}
		verifier := oauth2.GenerateVerifier()
		payload := adminOAuthStatePayload{
			Provider:     providerID,
			State:        state,
			CodeVerifier: verifier,
			Nonce:        nonce,
			ReturnTo:     sanitizeAdminReturnTo(r.URL.Query().Get("return_to"), store.AdminPath()),
			ExpiresAt:    time.Now().Add(adminOAuthStateTTL).Unix(),
		}
		signedState, err := signAdminOAuthState(payload, jwtSecret, store.Credentials().TokenSalt)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "state error"})
			return
		}
		setAdminOAuthStateCookie(w, r, signedState, trustedProxyHeaders)
		opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
		if nonce != "" {
			opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
		}
		http.Redirect(w, r, oauthConfig.AuthCodeURL(state, opts...), http.StatusFound)
	}
}

func handleAdminOAuthCallback(store *Store, jwtSecret string, trustedProxyHeaders bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		payload, err := verifyAdminOAuthStateCookie(r, jwtSecret, store.Credentials().TokenSalt)
		clearAdminOAuthStateCookie(w, r, trustedProxyHeaders)
		if err != nil {
			http.Error(w, "OAuth state invalid", http.StatusUnauthorized)
			return
		}
		if payload.State == "" || payload.State != r.URL.Query().Get("state") {
			http.Error(w, "OAuth state mismatch", http.StatusUnauthorized)
			return
		}
		if providerErr := strings.TrimSpace(r.URL.Query().Get("error")); providerErr != "" {
			http.Error(w, "OAuth provider rejected login", http.StatusUnauthorized)
			return
		}
		code := strings.TrimSpace(r.URL.Query().Get("code"))
		if code == "" {
			http.Error(w, "OAuth code missing", http.StatusBadRequest)
			return
		}

		settings := normalizeAdminAuthSettings(store.Credentials().AdminAuth)
		oauthConfig, provider, _, err := adminOAuthConfigForProvider(r.Context(), payload.Provider, settings, adminOAuthRedirectURI(r, trustedProxyHeaders))
		if err != nil {
			http.Error(w, "OAuth provider disabled", http.StatusUnauthorized)
			return
		}
		ctx := adminOAuthContext(r.Context())
		token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(payload.CodeVerifier))
		if err != nil {
			http.Error(w, "OAuth exchange failed", http.StatusUnauthorized)
			return
		}
		identity, err := adminOAuthIdentityForProvider(ctx, payload.Provider, settings, provider, token, payload.Nonce)
		if err != nil {
			http.Error(w, "OAuth identity rejected", http.StatusUnauthorized)
			return
		}
		if err := matchAdminOAuthIdentity(payload.Provider, settings, identity); err != nil {
			http.Error(w, "OAuth identity not allowed", http.StatusUnauthorized)
			return
		}
		if _, err := issueAdminSession(w, r, jwtSecret, store, trustedProxyHeaders); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		log.Printf("管理员 OAuth 登录: provider=%s login=%s email=%s remote=%s", payload.Provider, identity.Login, identity.Email, r.RemoteAddr)
		http.Redirect(w, r, forwardedPrefixedPath(r, payload.ReturnTo, trustedProxyHeaders), http.StatusFound)
	}
}

func adminOAuthConfigForProvider(ctx context.Context, providerID string, settings AdminAuthSettings, redirectURI string) (oauth2.Config, *oidc.Provider, string, error) {
	switch providerID {
	case adminOAuthProviderGitHub:
		if !githubOAuthReady(settings.GitHub) {
			return oauth2.Config{}, nil, "", errors.New("github oauth disabled")
		}
		return oauth2.Config{
			ClientID:     settings.GitHub.ClientID,
			ClientSecret: settings.GitHub.ClientSecret,
			RedirectURL:  redirectURI,
			Scopes:       settings.GitHub.Scopes,
			Endpoint:     github.Endpoint,
		}, nil, "", nil
	case adminOAuthProviderOIDC:
		if !oidcOAuthReady(settings.OIDC) {
			return oauth2.Config{}, nil, "", errors.New("oidc disabled")
		}
		provider, err := oidc.NewProvider(adminOAuthContext(ctx), settings.OIDC.IssuerURL)
		if err != nil {
			return oauth2.Config{}, nil, "", err
		}
		nonce, err := randomToken(32)
		if err != nil {
			return oauth2.Config{}, nil, "", err
		}
		return oauth2.Config{
			ClientID:     settings.OIDC.ClientID,
			ClientSecret: settings.OIDC.ClientSecret,
			RedirectURL:  redirectURI,
			Scopes:       settings.OIDC.Scopes,
			Endpoint:     provider.Endpoint(),
		}, provider, nonce, nil
	default:
		return oauth2.Config{}, nil, "", errors.New("unknown oauth provider")
	}
}

func adminOAuthIdentityForProvider(ctx context.Context, providerID string, settings AdminAuthSettings, provider *oidc.Provider, token *oauth2.Token, nonce string) (adminOAuthIdentity, error) {
	switch providerID {
	case adminOAuthProviderGitHub:
		return fetchGitHubOAuthIdentity(ctx, settings.GitHub, token)
	case adminOAuthProviderOIDC:
		return verifyOIDCOAuthIdentity(ctx, settings.OIDC, provider, token, nonce)
	default:
		return adminOAuthIdentity{}, errors.New("unknown oauth provider")
	}
}

func fetchGitHubOAuthIdentity(ctx context.Context, settings OAuth2ProviderSettings, token *oauth2.Token) (adminOAuthIdentity, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := fetchOAuthJSON(client, "https://api.github.com/user", &user); err != nil {
		return adminOAuthIdentity{}, err
	}
	identity := adminOAuthIdentity{
		Subject: fmt.Sprintf("%d", user.ID),
		Login:   strings.ToLower(strings.TrimSpace(user.Login)),
		Email:   strings.ToLower(strings.TrimSpace(user.Email)),
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := fetchOAuthJSON(client, "https://api.github.com/user/emails", &emails); err != nil {
		log.Printf("管理员 GitHub 邮箱获取失败: %v", err)
	} else {
		for _, item := range emails {
			email := strings.ToLower(strings.TrimSpace(item.Email))
			if email == "" {
				continue
			}
			if item.Primary || identity.Email == "" {
				identity.Email = email
				identity.EmailVerified = item.Verified
				if item.Primary {
					break
				}
			}
		}
	}
	return identity, nil
}

func fetchOAuthJSON(client *http.Client, endpoint string, target any) error {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "CyberMonitor")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("oauth provider returned %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(target)
}

func verifyOIDCOAuthIdentity(ctx context.Context, settings OIDCProviderSettings, provider *oidc.Provider, token *oauth2.Token, nonce string) (adminOAuthIdentity, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return adminOAuthIdentity{}, errors.New("id_token missing")
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: settings.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return adminOAuthIdentity{}, err
	}
	if nonce == "" || idToken.Nonce != nonce {
		return adminOAuthIdentity{}, errors.New("oidc nonce mismatch")
	}
	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return adminOAuthIdentity{}, err
	}
	login := strings.TrimSpace(claims.PreferredUsername)
	if login == "" {
		login = strings.TrimSpace(claims.Name)
	}
	return adminOAuthIdentity{
		Subject:       strings.TrimSpace(claims.Subject),
		Login:         login,
		Email:         strings.ToLower(strings.TrimSpace(claims.Email)),
		EmailVerified: claims.EmailVerified,
	}, nil
}

func matchAdminOAuthIdentity(providerID string, settings AdminAuthSettings, identity adminOAuthIdentity) error {
	switch providerID {
	case adminOAuthProviderGitHub:
		if containsString(settings.GitHub.AllowedLogins, strings.ToLower(identity.Login)) {
			return nil
		}
		return matchOAuthEmail(identity, settings.GitHub.AllowedEmails, settings.GitHub.AllowedEmailDomains, settings.GitHub.RequireVerifiedEmail)
	case adminOAuthProviderOIDC:
		if containsString(settings.OIDC.AllowedSubjects, identity.Subject) {
			return nil
		}
		return matchOAuthEmail(identity, settings.OIDC.AllowedEmails, settings.OIDC.AllowedEmailDomains, settings.OIDC.RequireVerifiedEmail)
	default:
		return errors.New("unknown oauth provider")
	}
}

func matchOAuthEmail(identity adminOAuthIdentity, allowedEmails, allowedDomains []string, requireVerified bool) error {
	email := strings.ToLower(strings.TrimSpace(identity.Email))
	if email == "" {
		return errors.New("email missing")
	}
	if requireVerified && !identity.EmailVerified {
		return errors.New("email not verified")
	}
	if containsString(allowedEmails, email) {
		return nil
	}
	if at := strings.LastIndex(email, "@"); at >= 0 {
		domain := email[at+1:]
		if containsString(allowedDomains, domain) {
			return nil
		}
	}
	return errors.New("email not allowed")
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func adminOAuthRedirectURI(r *http.Request, trustedProxyHeaders bool) string {
	scheme := "http"
	if requestIsSecure(r, trustedProxyHeaders) {
		scheme = "https"
	}
	host := "127.0.0.1"
	if r != nil && strings.TrimSpace(r.Host) != "" {
		host = strings.TrimSpace(r.Host)
	}
	return fmt.Sprintf("%s://%s%s/api/v1/login/oauth/callback", scheme, host, forwardedPrefix(r, trustedProxyHeaders))
}

func sanitizeAdminReturnTo(raw string, adminPath string) string {
	adminPath, err := normalizeAdminPath(adminPath)
	if err != nil {
		adminPath = "/admin"
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return adminPath
	}
	if strings.Contains(value, "\\") || strings.HasPrefix(value, "//") {
		return adminPath
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return adminPath
	}
	if parsed.Path == "" {
		parsed.Path = adminPath
	}
	if parsed.Path != adminPath && !strings.HasPrefix(parsed.Path, adminPath+"/") {
		return adminPath
	}
	parsed.Scheme = ""
	parsed.Host = ""
	parsed.User = nil
	return parsed.String()
}

func adminOAuthContext(ctx context.Context) context.Context {
	client := &http.Client{Timeout: adminOAuthHTTPTimeout}
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func signAdminOAuthState(payload adminOAuthStatePayload, secret string, tokenSalt string) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(data)
	mac := hmac.New(sha256.New, []byte(secret+"\x00"+tokenSalt))
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body + "." + sig, nil
}

func verifyAdminOAuthStateCookie(r *http.Request, secret string, tokenSalt string) (adminOAuthStatePayload, error) {
	cookie, err := r.Cookie(adminOAuthStateCookieName)
	if err != nil {
		return adminOAuthStatePayload{}, err
	}
	value := strings.TrimSpace(cookie.Value)
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return adminOAuthStatePayload{}, errors.New("state malformed")
	}
	mac := hmac.New(sha256.New, []byte(secret+"\x00"+tokenSalt))
	mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	actual, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(expected, actual) {
		return adminOAuthStatePayload{}, errors.New("state signature invalid")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return adminOAuthStatePayload{}, err
	}
	var payload adminOAuthStatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return adminOAuthStatePayload{}, err
	}
	if payload.ExpiresAt <= time.Now().Unix() {
		return adminOAuthStatePayload{}, errors.New("state expired")
	}
	return payload, nil
}

func setAdminOAuthStateCookie(w http.ResponseWriter, r *http.Request, value string, trustedProxyHeaders bool) {
	cookie := &http.Cookie{
		Name:     adminOAuthStateCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(adminOAuthStateTTL.Seconds()),
		Expires:  time.Now().Add(adminOAuthStateTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if requestIsSecure(r, trustedProxyHeaders) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

func clearAdminOAuthStateCookie(w http.ResponseWriter, r *http.Request, trustedProxyHeaders bool) {
	cookie := &http.Cookie{
		Name:     adminOAuthStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if requestIsSecure(r, trustedProxyHeaders) {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}
