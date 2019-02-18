/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, July 2018
*/

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"github.com/justinas/nosurf"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"gopkg.i-core.ru/werther/internal/ldapclient"
	"gopkg.i-core.ru/werther/internal/logger"
	"gopkg.i-core.ru/werther/internal/oauth2"
	"gopkg.i-core.ru/werther/internal/oauth2/hydra"
)

// Version will be filled at compile time.
var Version = ""

const internalServerErrorMessage = "Internal Server Error"

// Config is a server's configuration.
type Config struct {
	DevMode        bool              `envconfig:"dev_mode" default:"false" desc:"a development mode"`
	Listen         string            `default:":8080" desc:"a host and port to listen on (<host>:<port>)"`
	LDAPEndpoints  []string          `envconfig:"ldap_endpoints" required:"true" desc:"a LDAP's server URLs as \"<address>:<port>\""`
	LDAPBaseDN     string            `envconfig:"ldap_basedn" required:"true" desc:"a LDAP base DN"`
	LDAPBindDN     string            `envconfig:"ldap_binddn" desc:"a LDAP bind DN"`
	LDAPBindPW     string            `envconfig:"ldap_bindpw" json:"-" desc:"a LDAP bind password"`
	LDAPRoleBaseDN string            `envconfig:"ldap_role_basedn" required:"true" desc:"a LDAP base DN for searching roles"`
	LDAPRoleAttr   string            `envconfig:"ldap_role_attr" default:"description" desc:"a LDAP attribute for role's name"`
	LDAPAttrClaims map[string]string `envconfig:"ldap_attr_claims" default:"name:name,sn:family_name,givenName:given_name,mail:email" desc:"a mapping of LDAP attributes to OIDC claims"`
	ClaimScopes    map[string]string `envconfig:"claim_scopes" default:"name:profile,family_name:profile,given_name:profile,email:email,http%3A%2F%2Fi-core.ru%2Fclaims%2Froles:roles" desc:"a mapping of OIDC claims to scopes (all claims are URL encoded)"`
	SessionTTL     time.Duration     `envconfig:"session_ttl" default:"24h" desc:"a session TTL"`
	CacheSize      int               `envconfig:"cache_size" default:"512" desc:"a user info cache's size in KiB"`
	CacheTTL       time.Duration     `envconfig:"cache_ttl" default:"30m" desc:"a user info cache TTL"`
	HydraAdminURL  string            `envconfig:"hydra_admin_url" required:"true" desc:"a server admin URL of ORY Hydra"`
	WebDir         string            `envconfig:"web_dir" desc:"a path to an external web directory"`
	WebBasePath    string            `envconfig:"web_base_path" default:"/" desc:"a base path of web pages"`
}

// Server is a HTTP server that is a login provider.
type Server struct {
	Config
	router http.Handler
	webldr interface {
		loadTemplate(name string) (*template.Template, error)
	}
}

// New creates a new Server instance.
func New(cnf Config, log *zap.Logger) (*Server, error) {
	srv := &Server{Config: cnf}
	var err error
	if cnf.WebDir != "" {
		srv.webldr, err = newExtWebLoader(cnf.WebDir)
	} else {
		srv.webldr, err = newIntWebLoader()
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to init server")
	}

	ldapcnf := ldapclient.Config{
		Endpoints:  srv.LDAPEndpoints,
		BaseDN:     srv.LDAPBaseDN,
		BindDN:     srv.LDAPBindDN,
		BindPass:   srv.LDAPBindPW,
		RoleBaseDN: srv.LDAPRoleBaseDN,
		RoleAttr:   srv.LDAPRoleAttr,
		RoleClaim:  "http://i-core.ru/claims/roles",
		AttrClaims: srv.LDAPAttrClaims,
		CacheTTL:   srv.CacheTTL,
		CacheSize:  srv.CacheSize,
	}

	ldap := ldapclient.New(ldapcnf)
	router := httprouter.New()
	router.Handler(http.MethodGet, "/auth/login", srv.handleLoginStart(hydra.NewLoginReqDoer(cnf.HydraAdminURL)))
	router.Handler(http.MethodPost, "/auth/login", srv.handleLoginEnd(hydra.NewLoginReqDoer(cnf.HydraAdminURL), ldap))
	router.Handler(http.MethodGet, "/auth/consent", srv.handleConsent(hydra.NewConsentReqDoer(cnf.HydraAdminURL), ldap))

	router.Handler(http.MethodGet, "/health/alive", srv.handleHealthAliveAndReady())
	router.Handler(http.MethodGet, "/health/ready", srv.handleHealthAliveAndReady())
	router.Handler(http.MethodGet, "/version", srv.handleVersion())
	router.Handler(http.MethodGet, "/metrics/prometheus", promhttp.Handler())

	var fs http.FileSystem = http.Dir(path.Join(cnf.WebDir, "static"))
	if cnf.WebDir == "" { // Use embedded web templates
		fs = &assetfs.AssetFS{
			Asset:     Asset,
			AssetDir:  AssetDir,
			AssetInfo: AssetInfo,
			Prefix:    "static",
		}
	}
	router.ServeFiles("/static/*filepath", fs)

	srv.router = alice.New(nosurf.NewPure, logw(log.Sugar())).Then(router)

	return srv, nil
}

// ServeHTTP implements the http.Handler interface.
func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.router.ServeHTTP(w, r)
}

// oa2LoginReqAcceptor is an interface that is used for accepting an OAuth2 login request.
type oa2LoginReqAcceptor interface {
	AcceptLoginRequest(challenge string, remember bool, rememberFor int, subject string) (string, error)
}

// oa2LoginReqProcessor is an interface that is used for creating and accepting an OAuth2 login request.
//
// InitiateRequest returns oauth2.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
// InitiateRequest returns oauth2.ErrChallengeExpired if the OAuth2 provider processed the challenge previously.
type oa2LoginReqProcessor interface {
	InitiateRequest(challenge string) (*oauth2.ReqInfo, error)
	oa2LoginReqAcceptor
}

// loginTmplData is a data that is needed for rendering the login page.
type loginTmplData struct {
	CSRFToken            string
	Challenge            string
	LoginURL             string
	WebBasePath          string
	IsInvalidCredentials bool
	IsInternalError      bool
}

func (srv *Server) handleLoginStart(rproc oa2LoginReqProcessor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.FromContext(r.Context())
		challenge := r.URL.Query().Get("login_challenge")
		if challenge == "" {
			log.Debug("No login challenge that is needed by the OAuth2 provider")
			http.Error(w, "No login challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			log = log.With("challenge", challenge)
			switch errors.Cause(err) {
			case oauth2.ErrChallengeNotFound:
				log.Debugw("Unknown login challenge in the OAuth2 provider", "error", err)
				http.Error(w, "Unknown login challenge", http.StatusBadRequest)
				return
			case oauth2.ErrChallengeExpired:
				log.Debugw("Login challenge has been used already in the OAuth2 provider", "error", err)
				http.Error(w, "Login challenge has been used already", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to initiate an OAuth2 login request", "error", err)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
		log.Infow("A login request is initiated", "challenge", challenge, "username", ri.Subject)

		if ri.Skip {
			redirectURI, err := rproc.AcceptLoginRequest(challenge, false, 0, ri.Subject)
			if err != nil {
				log.Infow("Failed to accept an OAuth login request", "error", err)
				http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirectURI, http.StatusFound)
			return
		}

		data := loginTmplData{
			CSRFToken:   nosurf.Token(r),
			Challenge:   challenge,
			LoginURL:    strings.TrimPrefix(r.URL.String(), "/"),
			WebBasePath: srv.WebBasePath,
		}
		if err := srv.renderLoginTemplate(w, data); err != nil {
			log.Infow("Failed to render a login page template", "error", err)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
	}
}

// authenticator is an interface that is used for a user authentication.
//
// Authenticate returns false if the username or password is invalid.
type authenticator interface {
	Authenticate(ctx context.Context, username, password string) (ok bool, err error)
}

func (srv *Server) handleLoginEnd(ra oa2LoginReqAcceptor, auther authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.FromContext(r.Context())
		r.ParseForm()

		challenge := r.Form.Get("login_challenge")
		if challenge == "" {
			log.Debug("No login challenge that is needed by the OAuth2 provider")
			http.Error(w, "No login challenge", http.StatusBadRequest)
			return
		}

		data := loginTmplData{
			CSRFToken:   nosurf.Token(r),
			Challenge:   challenge,
			LoginURL:    r.URL.String(),
			WebBasePath: srv.WebBasePath,
		}

		username, password := r.Form.Get("username"), r.Form.Get("password")

		switch ok, err := auther.Authenticate(r.Context(), username, password); {
		case err != nil:
			data.IsInternalError = true
			log.Infow("Failed to authenticate a login request via the OAuth2 provider",
				"error", err, "challenge", challenge, "username", username)
			if err = srv.renderLoginTemplate(w, data); err != nil {
				log.Infow("Failed to render a login page template", "error", err)
				http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			}
			return
		case !ok:
			data.IsInvalidCredentials = true
			log.Debugw("Invalid credentials", "error", err, "challenge", challenge, "username", username)
			if err = srv.renderLoginTemplate(w, data); err != nil {
				log.Infow("Failed to render a login page template", "error", err)
				http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			}
			return
		}
		log.Infow("A username is authenticated", "challenge", challenge, "username", username)

		remember := r.Form.Get("remember") != ""
		redirectTo, err := ra.AcceptLoginRequest(challenge, remember, int(srv.SessionTTL.Seconds()), username)
		if err != nil {
			data.IsInternalError = true
			log.Infow("Failed to accept a login request via the OAuth2 provider", "error", err)
			if err := srv.renderLoginTemplate(w, data); err != nil {
				log.Infow("Failed to render a login page template", "error", err)
				http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			}
			return
		}

		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

// oa2ConsentReqAcceptor is an interface that is used for creating and accepting an OAuth2 consent request.
//
// InitiateRequest returns oauth2.ErrChallengeNotFound if the OAuth2 provider failed to find the challenge.
// InitiateRequest returns oauth2.ErrChallengeExpired if the OAuth2 provider processed the challenge previously.
type oa2ConsentReqProcessor interface {
	InitiateRequest(challenge string) (*oauth2.ReqInfo, error)
	AcceptConsentRequest(challenge string, remember bool, rememberFor int, grantScope []string, idToken interface{}) (string, error)
}

// oidcClaimsFinder is an interface that is used for searching OpenID Connect claims for the given username.
type oidcClaimsFinder interface {
	FindOIDCClaims(ctx context.Context, username string) (map[string]interface{}, error)
}

func (srv *Server) handleConsent(rproc oa2ConsentReqProcessor, cfinder oidcClaimsFinder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.FromContext(r.Context())

		challenge := r.URL.Query().Get("consent_challenge")
		if challenge == "" {
			log.Debug("No consent challenge that is needed by the OAuth2 provider")
			http.Error(w, "No consent challenge", http.StatusBadRequest)
			return
		}

		ri, err := rproc.InitiateRequest(challenge)
		if err != nil {
			log = log.With("challenge", challenge)
			switch errors.Cause(err) {
			case oauth2.ErrChallengeNotFound:
				log.Debugw("Unknown consent challenge in the OAuth2 provider", "error", err)
				http.Error(w, "Unknown consent challenge", http.StatusBadRequest)
				return
			case oauth2.ErrChallengeExpired:
				log.Debugw("Consent challenge has been used already in the OAuth2 provider", "error", err)
				http.Error(w, "Consent challenge has been used already", http.StatusBadRequest)
				return
			}
			log.Infow("Failed to send an OAuth2 consent request", "error", err)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
		log.Infow("A consent request is initiated", "challenge", challenge, "username", ri.Subject)

		claims, err := cfinder.FindOIDCClaims(r.Context(), ri.Subject)
		if err != nil {
			log.Infow("Failed to find user's OIDC claims", "error", err)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
		log.Debugw("Found user's OIDC claims", "claims", claims)

		// Remove claims that are not in the requested scopes.
		for claim := range claims {
			var found bool
			// We need to escape a claim due to ClaimScopes' keys contain URL encoded claims.
			// It is because of config option's format compatibility.
			if scope, ok := srv.ClaimScopes[url.QueryEscape(claim)]; ok {
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
		redirectTo, err := rproc.AcceptConsentRequest(challenge, !ri.Skip, int(srv.SessionTTL.Seconds()), ri.RequestedScopes, claims)
		if err != nil {
			log.Infow("Failed to accept a consent request to the OAuth2 provider", "error", err, "scopes", ri.RequestedScopes, "claims", claims)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
		log.Debugw("Accepted the consent request to the OAuth2 provider", "scopes", ri.RequestedScopes, "claims", claims)
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

func (srv *Server) renderLoginTemplate(w http.ResponseWriter, data interface{}) error {
	t, err := srv.webldr.loadTemplate("login.tmpl")
	if err != nil {
		return err
	}
	var (
		buf bytes.Buffer
		bw  = bufio.NewWriter(&buf)
	)
	if err := t.Execute(bw, data); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
	return nil
}

func (srv *Server) handleHealthAliveAndReady() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.FromContext(r.Context())
		resp := struct {
			Status string `json:"status"`
		}{
			Status: "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Infow("Failed to marshal health liveness and readiness status", "error", err)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
	}
}

func (srv *Server) handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.FromContext(r.Context())
		resp := struct {
			Version string `json:"version"`
		}{
			Version: Version,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Infow("Failed to marshal version", "error", err)
			http.Error(w, internalServerErrorMessage, http.StatusInternalServerError)
			return
		}
	}
}
