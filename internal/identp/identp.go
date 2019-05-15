/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential
*/

// Package identp is an implementation of [Login and Consent Flow](https://www.ory.sh/docs/hydra/oauth2)
// between ORY Hydra and Werther Identity Provider.
package identp

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/justinas/nosurf"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.i-core.ru/logutil"
	"gopkg.i-core.ru/werther/internal/hydra"
)

const loginTmplName = "login.tmpl"

// Config is a Hydra configuration.
type Config struct {
	HydraURL    string            `envconfig:"hydra_url" required:"true" desc:"a server admin URL of ORY Hydra"`
	SessionTTL  time.Duration     `envconfig:"session_ttl" default:"24h" desc:"a session TTL"`
	ClaimScopes map[string]string `envconfig:"claim_scopes" default:"name:profile,family_name:profile,given_name:profile,email:email,http%3A%2F%2Fi-core.ru%2Fclaims%2Froles:roles" desc:"a mapping of OIDC claims to scopes (all claims are URL encoded)"`
}

// UserManager is an interface that is used for authentication and providing user's claims.
type UserManager interface {
	authenticator
	oidcClaimsFinder
}

// authenticator is an interface that is used for a user authentication.
//
// Authenticate returns false if the username or password is invalid.
type authenticator interface {
	Authenticate(ctx context.Context, username, password string) (ok bool, err error)
}

// oidcClaimsFinder is an interface that is used for searching OpenID Connect claims for the given username.
type oidcClaimsFinder interface {
	FindOIDCClaims(ctx context.Context, username string) (map[string]interface{}, error)
}

// TemplateRenderer renders a template with data and writes it to a http.ResponseWriter.
type TemplateRenderer interface {
	RenderTemplate(w http.ResponseWriter, name string, data interface{}) error
}

// LoginTmplData is a data that is needed for rendering the login page.
type LoginTmplData struct {
	CSRFToken            string
	Challenge            string
	LoginURL             string
	IsInvalidCredentials bool
	IsInternalError      bool
}

// Handler provides HTTP handlers that implement [Login and Consent Flow](https://www.ory.sh/docs/hydra/oauth2)
// between ORY Hydra and Werther Identity Provider.
type Handler struct {
	Config
	um UserManager
	tr TemplateRenderer
}

// NewHandler creates a new Handler.
//
// The template's renderer must be able to render a template with name "login.tmpl".
// The template is a template of the login page. It receives struct LoginTmplData as template's data.
func NewHandler(cnf Config, um UserManager, tr TemplateRenderer) *Handler {
	return &Handler{Config: cnf, um: um, tr: tr}
}

// AddRoutes registers all required routes for Login & Consent Provider.
func (h *Handler) AddRoutes(apply func(m, p string, h http.Handler, mws ...func(http.Handler) http.Handler)) {
	sessionTTL := int(h.SessionTTL.Seconds())
	apply(http.MethodGet, "/login", newLoginStartHandler(hydra.NewLoginReqDoer(h.HydraURL, 0), h.tr))
	apply(http.MethodPost, "/login", newLoginEndHandler(hydra.NewLoginReqDoer(h.HydraURL, sessionTTL), h.um, h.tr))
	apply(http.MethodGet, "/consent", newConsentHandler(hydra.NewConsentReqDoer(h.HydraURL, sessionTTL), h.um, h.ClaimScopes))
	apply(http.MethodGet, "/logout", newLogoutHandler(hydra.NewLogoutReqDoer(h.HydraURL)))
}

// oa2LoginReqAcceptor is an interface that is used for accepting an OAuth2 login request.
type oa2LoginReqAcceptor interface {
	AcceptLoginRequest(challenge string, remember bool, subject string) (string, error)
}

// oa2LoginReqProcessor is an interface that is used for creating and accepting an OAuth2 login request.
//
// InitiateRequest returns hydra.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
// InitiateRequest returns hydra.ErrChallengeExpired if the OAuth2 provider processed the challenge previously.
type oa2LoginReqProcessor interface {
	InitiateRequest(challenge string) (*hydra.ReqInfo, error)
	oa2LoginReqAcceptor
}

func newLoginStartHandler(rproc oa2LoginReqProcessor, tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logutil.FromContext(r.Context()).Sugar()
		challenge := r.URL.Query().Get("login_challenge")
		if challenge == "" {
			log.Debug("No login challenge that is needed by the OAuth2 provider")
			http.Error(w, "No login challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			switch errors.Cause(err) {
			case hydra.ErrChallengeNotFound:
				log.Debugw("Unknown login challenge in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Unknown login challenge", http.StatusBadRequest)
				return
			case hydra.ErrChallengeExpired:
				log.Debugw("Login challenge has been used already in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Login challenge has been used already", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to initiate an OAuth2 login request", zap.Error(err), "challenge", challenge)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Infow("A login request is initiated", "challenge", challenge, "username", ri.Subject)

		if ri.Skip {
			redirectURI, err := rproc.AcceptLoginRequest(challenge, false, ri.Subject)
			if err != nil {
				log.Infow("Failed to accept an OAuth login request", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}

		data := LoginTmplData{
			CSRFToken: nosurf.Token(r),
			Challenge: challenge,
			LoginURL:  strings.TrimPrefix(r.URL.String(), "/"),
		}
		if err := tmplRenderer.RenderTemplate(w, loginTmplName, data); err != nil {
			log.Infow("Failed to render a login page template", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func newLoginEndHandler(ra oa2LoginReqAcceptor, auther authenticator, tmplRenderer TemplateRenderer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logutil.FromContext(r.Context()).Sugar()
		r.ParseForm()

		challenge := r.Form.Get("login_challenge")
		if challenge == "" {
			log.Debug("No login challenge that is needed by the OAuth2 provider")
			http.Error(w, "No login challenge", http.StatusBadRequest)
			return
		}

		data := LoginTmplData{
			CSRFToken: nosurf.Token(r),
			Challenge: challenge,
			LoginURL:  r.URL.String(),
		}

		username, password := r.Form.Get("username"), r.Form.Get("password")

		switch ok, err := auther.Authenticate(r.Context(), username, password); {
		case err != nil:
			data.IsInternalError = true
			log.Infow("Failed to authenticate a login request via the OAuth2 provider",
				zap.Error(err), "challenge", challenge, "username", username)
			if err = tmplRenderer.RenderTemplate(w, loginTmplName, data); err != nil {
				log.Infow("Failed to render a login page template", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		case !ok:
			data.IsInvalidCredentials = true
			log.Debugw("Invalid credentials", zap.Error(err), "challenge", challenge, "username", username)
			if err = tmplRenderer.RenderTemplate(w, loginTmplName, data); err != nil {
				log.Infow("Failed to render a login page template", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}
		log.Infow("A username is authenticated", "challenge", challenge, "username", username)

		remember := r.Form.Get("remember") != ""
		redirectTo, err := ra.AcceptLoginRequest(challenge, remember, username)
		if err != nil {
			data.IsInternalError = true
			log.Infow("Failed to accept a login request via the OAuth2 provider", zap.Error(err))
			if err := tmplRenderer.RenderTemplate(w, loginTmplName, data); err != nil {
				log.Infow("Failed to render a login page template", zap.Error(err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}

		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

// oa2ConsentReqAcceptor is an interface that is used for creating and accepting an OAuth2 consent request.
//
// InitiateRequest returns hydra.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
// InitiateRequest returns hydra.ErrChallengeExpired if the OAuth2 provider processed the challenge previously.
type oa2ConsentReqProcessor interface {
	InitiateRequest(challenge string) (*hydra.ReqInfo, error)
	AcceptConsentRequest(challenge string, remember bool, grantScope []string, idToken interface{}) (string, error)
}

func newConsentHandler(rproc oa2ConsentReqProcessor, cfinder oidcClaimsFinder, claimScopes map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logutil.FromContext(r.Context()).Sugar()

		challenge := r.URL.Query().Get("consent_challenge")
		if challenge == "" {
			log.Debug("No consent challenge that is needed by the OAuth2 provider")
			http.Error(w, "No consent challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			switch errors.Cause(err) {
			case hydra.ErrChallengeNotFound:
				log.Debugw("Unknown consent challenge in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Unknown consent challenge", http.StatusBadRequest)
				return
			case hydra.ErrChallengeExpired:
				log.Debugw("Consent challenge has been used already in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Consent challenge has been used already", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to send an OAuth2 consent request", zap.Error(err), "challenge", challenge)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Infow("A consent request is initiated", "challenge", challenge, "username", ri.Subject)

		claims, err := cfinder.FindOIDCClaims(r.Context(), ri.Subject)
		if err != nil {
			log.Infow("Failed to find user's OIDC claims", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Debugw("Found user's OIDC claims", "claims", claims)

		// Remove claims that are not in the requested scopes.
		for claim := range claims {
			var found bool
			// We need to escape a claim due to ClaimScopes' keys contain URL encoded claims.
			// It is because of config option's format compatibility.
			if scope, ok := claimScopes[url.QueryEscape(claim)]; ok {
				for _, rscope := range ri.RequestedScopes {
					if rscope == scope {
						found = true
						break
					}
				}
			}
			if !found {
				delete(claims, claim)
				log.Debugw("Deleted the OIDC claim because it's not in requested scopes", "claim", claim)
			}
		}
		redirectTo, err := rproc.AcceptConsentRequest(challenge, !ri.Skip, ri.RequestedScopes, claims)
		if err != nil {
			log.Infow("Failed to accept a consent request to the OAuth2 provider", zap.Error(err), "scopes", ri.RequestedScopes, "claims", claims)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Debugw("Accepted the consent request to the OAuth2 provider", "scopes", ri.RequestedScopes, "claims", claims)
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

// oa2LogoutReqProcessor is an interface that is used for creating and accepting an OAuth2 logout request.
//
// InitiateRequest returns hydra.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
type oa2LogoutReqProcessor interface {
	InitiateRequest(challenge string) (*hydra.ReqInfo, error)
	AcceptLogoutRequest(challenge string) (string, error)
}

func newLogoutHandler(rproc oa2LogoutReqProcessor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logutil.FromContext(r.Context()).Sugar()

		challenge := r.URL.Query().Get("logout_challenge")
		if challenge == "" {
			log.Debug("No logout challenge that is needed by the OAuth2 provider")
			http.Error(w, "No logout challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			switch errors.Cause(err) {
			case hydra.ErrChallengeNotFound:
				log.Debugw("Unknown logout challenge in the OAuth2 provider", zap.Error(err), "challenge", challenge)
				http.Error(w, "Unknown logout challenge", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to send an OAuth2 logout request", zap.Error(err), "challenge", challenge)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Infow("A logout request is initiated", "challenge", challenge, "username", ri.Subject)

		redirectTo, err := rproc.AcceptLogoutRequest(challenge)
		if err != nil {
			log.Infow("Failed to accept the logout request to the OAuth2 provider", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Debugw("Accepted the logout request to the OAuth2 provider")
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}
