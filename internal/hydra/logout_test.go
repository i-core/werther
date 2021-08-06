package hydra_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/i-core/werther/internal/hydra"
	"github.com/pkg/errors"
)

func TestInitiateLogoutRequest(t *testing.T) {
	testCases := []struct {
		name      string
		challenge string
		reqInfo   *hydra.ReqInfo
		status    int
		wantErr   error
	}{
		{
			name:    "challenge is missed",
			wantErr: hydra.ErrChallengeMissed,
		},
		{
			name:      "challenge is not found",
			challenge: "foo",
			status:    404,
			wantErr:   hydra.ErrChallengeNotFound,
		},
		{
			name:      "happy path",
			challenge: "foo",
			status:    200,
			reqInfo: &hydra.ReqInfo{
				Challenge: "foo",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &testInitiateLogoutHandler{reqInfo: tc.reqInfo, status: tc.status}
			srv := httptest.NewServer(h)
			defer srv.Close()
			ldr := hydra.NewLogoutReqDoer(srv.URL, false)

			reqInfo, err := ldr.InitiateRequest(tc.challenge)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("\ngot no errors\nwant error:\n\t%s", tc.wantErr)
				}
				err = errors.Cause(err)
				if err != tc.wantErr {
					t.Fatalf("\ngot error:\n\t%s\nwant error:\n\t%s", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("\ngot error:\n\t%s\nwant no errors", err)
			}

			if h.challenge != tc.challenge {
				t.Errorf("\ngot challenge:\n\t%#v\nwant challenge:\n\t%#v", h.challenge, tc.challenge)
			}
			if !reflect.DeepEqual(tc.reqInfo, reqInfo) {
				t.Errorf("\ngot request info:\n\t%#v\nwant request info:\n\t%#v", reqInfo, tc.reqInfo)
			}
		})
	}
}

type testInitiateLogoutHandler struct {
	reqInfo   *hydra.ReqInfo
	status    int
	challenge string
}

func (h *testInitiateLogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/oauth2/auth/requests/logout" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"error": http.StatusText(http.StatusMethodNotAllowed)}); err != nil {
			panic(fmt.Sprintf("initial request: failed to write response: %s", err))
		}
		return
	}
	h.challenge = r.URL.Query().Get("logout_challenge")
	w.WriteHeader(h.status)
	if h.status == http.StatusOK {
		if err := json.NewEncoder(w).Encode(h.reqInfo); err != nil {
			panic(fmt.Sprintf("initial request: failed to write response: %s", err))
		}
	}
}

func TestAcceptLogoutRequest(t *testing.T) {
	testCases := []struct {
		name      string
		challenge string
		status    int
		redirect  string
		wantErr   error
	}{
		{
			name:    "challenge is missed",
			wantErr: hydra.ErrChallengeMissed,
		},
		{
			name:      "challenge is not found",
			challenge: "foo",
			status:    http.StatusNotFound,
			wantErr:   hydra.ErrChallengeNotFound,
		},
		{
			name:      "happy path",
			challenge: "foo",
			status:    http.StatusOK,
			redirect:  "/test-redirect",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &testAcceptLogoutHandler{challenge: tc.challenge, status: tc.status, redirect: tc.redirect}
			srv := httptest.NewServer(h)
			defer srv.Close()
			ldr := hydra.NewLogoutReqDoer(srv.URL, false)

			redirect, err := ldr.AcceptLogoutRequest(tc.challenge)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("\ngot no errors\nwant error:\n\t%s", tc.wantErr)
				}
				err = errors.Cause(err)
				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("\ngot error:\n\t%s\nwant error:\n\t%s", err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("\ngot error:\n\t%s\nwant no errors", err)
			}

			if h.challenge != tc.challenge {
				t.Errorf("\ngot challenge:\n\t%#v\nwant challenge:\n\t%#v", h.challenge, tc.challenge)
			}
			if redirect != tc.redirect {
				t.Errorf("\ngot redirect URL:\n\t%#v\nwant redirect URL:\n\t%#v", redirect, tc.redirect)
			}
		})
	}
}

type testAcceptLogoutHandler struct {
	challenge string
	status    int
	redirect  string
}

func (h *testAcceptLogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut || r.URL.Path != "/oauth2/auth/requests/logout/accept" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	h.challenge = r.URL.Query().Get("logout_challenge")
	w.WriteHeader(h.status)
	if h.status == http.StatusOK {
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"redirect_to": h.redirect}); err != nil {
			panic(fmt.Sprintf("accept request: failed to write response: %s", err))
		}
	}
}
