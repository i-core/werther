/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package identp

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/i-core/werther/internal/hydra"
	"github.com/justinas/nosurf"
	"github.com/pkg/errors"
)

func TestHandleLoginStart(t *testing.T) {
	testCases := []struct {
		name          string
		challenge     string
		scopes        []string
		skip          bool
		subject       string
		redirect      string
		wantStatus    int
		wantInitErr   error
		wantAcceptErr error
		wantLoc       string
		wantBody      string
	}{
		{
			name:       "no login challenge",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "happy path",
			challenge:  "foo",
			wantStatus: http.StatusOK,
			wantBody: `
				LoginURL: login?login_challenge=foo;
				CSRFToken:  true;
				Challenge: foo;
			`,
		},
		{
			name:       "skip",
			challenge:  "foo",
			skip:       true,
			wantLoc:    "/",
			wantStatus: http.StatusFound,
		},
		{
			name:        "unknown challenge",
			challenge:   "foo",
			wantInitErr: hydra.ErrChallengeNotFound,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "used challenge",
			challenge:   "foo",
			wantInitErr: hydra.ErrChallengeExpired,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "init error",
			challenge:   "foo",
			wantInitErr: errors.New("init error"),
			wantStatus:  http.StatusInternalServerError,
		},
		{
			name:          "accept error",
			challenge:     "foo",
			skip:          true,
			wantAcceptErr: errors.New("accept error"),
			wantStatus:    http.StatusInternalServerError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/login"
			if tc.challenge != "" {
				url += "?login_challenge=" + tc.challenge
			}
			r, err := http.NewRequest("POST", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "gopkg.example.org"
			rr := httptest.NewRecorder()

			tmplRenderer := &testTemplateRenderer{
				renderTmplFunc: func(w http.ResponseWriter, r *http.Request, name string, data interface{}) error {
					if name != "login.tmpl" {
						t.Fatalf("wrong template name: got %q; want \"login.tmpl\"", name)
					}

					const loginT = `
						LoginURL: {{ .LoginURL }};
						CSRFToken: {{ if .CSRFToken }} true {{- else -}} false {{- end }};
						Challenge: {{ .Challenge }};
					`
					tmpl, err := template.New("login").Parse(loginT)
					if err != nil {
						t.Fatalf("failed to parse template: %s", err)
					}
					return tmpl.Execute(w, data)
				},
			}
			rproc := testLoginReqProc{
				initReqFunc: func(challenge string) (*hydra.ReqInfo, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while initiating the request: got %q; want %q", challenge, tc.challenge)
					}
					return &hydra.ReqInfo{
						Challenge:       tc.challenge,
						RequestedScopes: tc.scopes,
						Skip:            tc.skip,
						Subject:         tc.subject,
					}, tc.wantInitErr
				},
				acceptReqFunc: func(challenge string, remember bool, subject string) (string, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while accepting the request: got %q; want %q", challenge, tc.challenge)
					}
					if remember {
						t.Error("unexpected enabled remember flag")
					}
					if subject != tc.subject {
						t.Errorf("wrong subject while accepting the request: got %q; want %q", subject, tc.subject)
					}
					return tc.redirect, tc.wantAcceptErr
				},
			}
			handler := nosurf.New(newLoginStartHandler(rproc, tmplRenderer))
			handler.ExemptPath("/login")
			handler.ServeHTTP(rr, r)

			if status := rr.Code; status != tc.wantStatus {
				t.Errorf("wrong status code: got %v; want %v", status, tc.wantStatus)
			}
			wantBody, gotBody := noindent(tc.wantBody), noindent(rr.Body.String())
			if wantBody != "" && gotBody != wantBody {
				t.Errorf("wrong body:\ngot  %q\nwant %q", gotBody, wantBody)
			}
			if gotLoc := rr.Header().Get("Location"); gotLoc != tc.wantLoc {
				t.Errorf("wrong location:\ngot  %q\nwant %q", gotLoc, tc.wantLoc)
			}
		})
	}
}

func noindent(s string) string {
	wsRe := regexp.MustCompile(`(?:^\s+|(;)\s+)`)
	return wsRe.ReplaceAllString(s, "$1 ")
}

type testLoginReqProc struct {
	initReqFunc   func(string) (*hydra.ReqInfo, error)
	acceptReqFunc func(string, bool, string) (string, error)
}

func (lrp testLoginReqProc) InitiateRequest(challenge string) (*hydra.ReqInfo, error) {
	return lrp.initReqFunc(challenge)
}

func (lrp testLoginReqProc) AcceptLoginRequest(challenge string, remember bool, subject string) (string, error) {
	return lrp.acceptReqFunc(challenge, remember, subject)
}

func TestHandleLoginEnd(t *testing.T) {
	testCases := []struct {
		name          string
		challenge     string
		subject       string
		webBasePath   string
		redirect      string
		wantStatus    int
		wantAcceptErr error
		wantAuthErr   error
		wantInvAuth   bool
		wantLoc       string
		wantBody      string
	}{
		{
			name:       "no login challenge",
			subject:    "joe",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "happy path",
			challenge:  "foo",
			subject:    "joe",
			redirect:   "/redirect-to",
			wantStatus: http.StatusFound,
			wantLoc:    "/redirect-to",
		},
		{
			name:        "auth unknown error",
			challenge:   "foo",
			subject:     "joe",
			webBasePath: "testBasePath",
			wantStatus:  http.StatusOK,
			wantInvAuth: false,
			wantAuthErr: errors.New("Unknown error"),
			wantBody: `
				LoginURL: /login;
				CSRFToken: T;
				Challenge: foo;
				InvCreds: F;
				IsIntErr: T;
			`,
		},
		{
			name:        "unauth error",
			challenge:   "foo",
			subject:     "joe",
			wantStatus:  http.StatusOK,
			wantInvAuth: true,
			wantBody: `
				LoginURL: /login;
				CSRFToken: T;
				Challenge: foo;
				InvCreds: T;
				IsIntErr: F;
			`,
		},
		{
			name:          "accept error",
			challenge:     "foo",
			subject:       "joe",
			wantStatus:    http.StatusOK,
			wantAcceptErr: errors.New("accept error"),
			wantBody: `
				LoginURL: /login;
				CSRFToken: T;
				Challenge: foo;
				InvCreds: F;
				IsIntErr: T;
			`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/login"
			ps := "username=joe&password=pass"
			if tc.challenge != "" {
				ps += "&login_challenge=" + tc.challenge
			}
			r, err := http.NewRequest("POST", url, strings.NewReader(ps))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "gopkg.example.org"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			tmplRenderer := &testTemplateRenderer{
				renderTmplFunc: func(w http.ResponseWriter, r *http.Request, name string, data interface{}) error {
					if name != "login.tmpl" {
						t.Fatalf("wrong template name: got %q; want \"login.tmpl\"", name)
					}

					const loginT = `
						LoginURL: {{ .LoginURL }};
						CSRFToken: {{ if .CSRFToken -}} T {{- else -}} F {{- end }};
						Challenge: {{ .Challenge }};
						InvCreds: {{ if .IsInvalidCredentials -}} T {{- else -}} F {{- end }};
						IsIntErr: {{ if .IsInternalError -}} T {{- else -}} F {{- end}};
					`
					tmpl, err := template.New("login").Parse(loginT)
					if err != nil {
						t.Fatalf("failed to parse template: %s", err)
					}
					return tmpl.Execute(w, data)
				},
			}
			rproc := testLoginReqProc{
				acceptReqFunc: func(challenge string, remember bool, subject string) (string, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while accepting the request: got %q; want %q", challenge, tc.challenge)
					}
					if remember {
						t.Error("unexpected enabled remember flag")
					}
					if subject != tc.subject {
						t.Errorf("wrong subject while accepting the request: got %q; want %q", subject, tc.subject)
					}
					return tc.redirect, tc.wantAcceptErr
				},
			}
			auther := testAuthenticator{
				authnFunc: func(ctx context.Context, username, password string) (bool, error) {
					if username == "" {
						t.Error("unexpected empty username")
					}
					if password == "" {
						t.Error("unexpected empty password")
					}
					return !tc.wantInvAuth, tc.wantAuthErr
				},
			}
			handler := nosurf.New(newLoginEndHandler(rproc, auther, tmplRenderer))
			handler.ExemptPath("/login")
			handler.ServeHTTP(rr, r)

			if status := rr.Code; status != tc.wantStatus {
				t.Errorf("wrong status code: got %v; want %v", status, tc.wantStatus)
			}
			wantBody, gotBody := noindent(tc.wantBody), noindent(rr.Body.String())
			if wantBody != "" && gotBody != wantBody {
				t.Errorf("wrong body:\ngot  %q\nwant %q", gotBody, wantBody)
			}
			if gotLoc := rr.Header().Get("Location"); gotLoc != tc.wantLoc {
				t.Errorf("wrong location:\ngot  %q\nwant %q", gotLoc, tc.wantLoc)
			}
		})
	}
}

type testTemplateRenderer struct {
	renderTmplFunc func(w http.ResponseWriter, r *http.Request, name string, data interface{}) error
}

func (tl *testTemplateRenderer) RenderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) error {
	return tl.renderTmplFunc(w, r, name, data)
}

type testAuthenticator struct {
	authnFunc func(context.Context, string, string) (bool, error)
}

func (au testAuthenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	return au.authnFunc(ctx, username, password)
}

func TestHandleConsent(t *testing.T) {
	testCases := []struct {
		name          string
		challenge     string
		redirect      string
		subject       string
		skip          bool
		claims        map[string]interface{}
		scopes        []string
		wantStatus    int
		wantAcceptErr error
		wantInitErr   error
		wantFindErr   error
		wantLoc       string
	}{
		{
			name:       "no login challenge",
			subject:    "joe",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:        "unknown challenge",
			challenge:   "foo",
			wantInitErr: hydra.ErrChallengeNotFound,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "used challenge",
			challenge:   "foo",
			wantInitErr: hydra.ErrChallengeExpired,
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:       "happy path",
			challenge:  "foo",
			subject:    "joe",
			redirect:   "/redirect-to",
			wantStatus: http.StatusFound,
			wantLoc:    "/redirect-to",
			claims:     map[string]interface{}{"a": "foo", "b": "bar", "c": "baz"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/consent"
			if tc.challenge != "" {
				url += "?consent_challenge=" + tc.challenge
			}
			r, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "gopkg.example.org"
			rr := httptest.NewRecorder()

			rproc := testConsentReqProc{
				initReqFunc: func(challenge string) (*hydra.ReqInfo, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while initiating the request: got %q; want %q", challenge, tc.challenge)
					}
					return &hydra.ReqInfo{
						Challenge:       tc.challenge,
						Subject:         tc.subject,
						RequestedScopes: tc.scopes,
					}, tc.wantInitErr
				},
				acceptReqFunc: func(challenge string, remember bool, grantScope []string, idToken interface{}) (string, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while accepting the request: got %q; want %q", challenge, tc.challenge)
					}
					if remember == tc.skip {
						t.Error("unexpected enabled remember flag")
					}
					if len(grantScope) != len(tc.scopes) {
						t.Errorf("wrong granted scopes while accepting the request: got %q; want %q", grantScope, tc.scopes)
					} else {
						for i := range grantScope {
							if grantScope[i] != tc.scopes[i] {
								t.Errorf("wrong granted scopes while accepting the request: got %q; want %q", grantScope, tc.scopes)
								break
							}
						}
					}
					if !reflect.DeepEqual(idToken, tc.claims) {
						t.Errorf("wrong an id token while accepting the request: got %q; want %q", idToken, tc.claims)
					}
					return tc.redirect, tc.wantAcceptErr
				},
			}
			cfinder := testOIDCClaimsFinder{
				findFunc: func(ctx context.Context, username string) (map[string]interface{}, error) {
					if username == "" {
						t.Error("unexpected empty username")
					}
					return tc.claims, tc.wantFindErr
				},
			}
			handler := nosurf.New(newConsentHandler(rproc, cfinder, nil))
			handler.ExemptPath("/consent")
			handler.ServeHTTP(rr, r)

			if status := rr.Code; status != tc.wantStatus {
				t.Errorf("wrong status code: got %v; want %v", status, tc.wantStatus)
			}
			if gotLoc := rr.Header().Get("Location"); gotLoc != tc.wantLoc {
				t.Errorf("wrong location:\ngot  %q\nwant %q", gotLoc, tc.wantLoc)
			}
		})
	}
}

type testConsentReqProc struct {
	initReqFunc   func(string) (*hydra.ReqInfo, error)
	acceptReqFunc func(string, bool, []string, interface{}) (string, error)
}

func (crp testConsentReqProc) InitiateRequest(challenge string) (*hydra.ReqInfo, error) {
	return crp.initReqFunc(challenge)
}

func (crp testConsentReqProc) AcceptConsentRequest(challenge string, remember bool, grantScope []string, idToken interface{}) (string, error) {
	return crp.acceptReqFunc(challenge, remember, grantScope, idToken)
}

type testOIDCClaimsFinder struct {
	findFunc func(context.Context, string) (map[string]interface{}, error)
}

func (cf testOIDCClaimsFinder) FindOIDCClaims(ctx context.Context, username string) (map[string]interface{}, error) {
	return cf.findFunc(ctx, username)
}

func TestLogoutHandler(t *testing.T) {
	testCases := []struct {
		name       string
		challenge  string
		initErr    error
		acceptErr  error
		redirectTo string
		wantStatus int
		wantLoc    string
	}{
		{
			name:       "no login challenge",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown challenge",
			challenge:  "foo",
			initErr:    hydra.ErrChallengeNotFound,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "init logout request error",
			challenge:  "foo",
			initErr:    fmt.Errorf("init logout request error"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "accept logout request error",
			challenge:  "foo",
			acceptErr:  fmt.Errorf("accept logout request error"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "happy path",
			challenge:  "foo",
			redirectTo: "/redirect-to",
			wantStatus: http.StatusFound,
			wantLoc:    "/redirect-to",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/logout"
			if tc.challenge != "" {
				url += "?logout_challenge=" + tc.challenge
			}
			r, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Host = "gopkg.example.org"
			rr := httptest.NewRecorder()

			rproc := &testLogoutReqProc{
				initReqFunc: func(challenge string) (*hydra.ReqInfo, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while initiating the request: got %q; want %q", challenge, tc.challenge)
					}
					return &hydra.ReqInfo{}, tc.initErr
				},
				acceptReqFunc: func(challenge string) (string, error) {
					if challenge != tc.challenge {
						t.Errorf("wrong challenge while accepting the request: got %q; want %q", challenge, tc.challenge)
					}
					return tc.redirectTo, tc.acceptErr
				},
			}
			handler := newLogoutHandler(rproc)
			handler.ServeHTTP(rr, r)

			if rr.Code != tc.wantStatus {
				t.Errorf("wrong status code: got %v; want %v", rr.Code, tc.wantStatus)
			}
			if gotLoc := rr.Header().Get("Location"); gotLoc != tc.wantLoc {
				t.Errorf("wrong location:\ngot  %q\nwant %q", gotLoc, tc.wantLoc)
			}
		})
	}
}

type testLogoutReqProc struct {
	initReqFunc   func(string) (*hydra.ReqInfo, error)
	acceptReqFunc func(string) (string, error)
}

func (p *testLogoutReqProc) InitiateRequest(challenge string) (*hydra.ReqInfo, error) {
	return p.initReqFunc(challenge)
}

func (p *testLogoutReqProc) AcceptLogoutRequest(challenge string) (string, error) {
	return p.acceptReqFunc(challenge)
}
