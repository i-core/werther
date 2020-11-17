/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package web

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/andreyvit/diff"
	"github.com/i-core/routegroup"
)

func TestHTMLRenderer(t *testing.T) {
	testCases := []struct {
		name     string
		ext      bool
		basePath string
		data     interface{}
		wantErr  error
	}{
		{
			name:    "internal template not found",
			wantErr: fmt.Errorf(`the template "login.tmpl" does not exist`),
		},
		{
			name:     "internal template happy path",
			basePath: "testBasePath",
			data: map[string]interface{}{
				"CSRFToken":            "testCSRFToken",
				"Challenge":            "testChalenge",
				"LoginURL":             "testLoginURL",
				"IsInvalidCredentials": true,
				"IsInternalError":      true,
			},
		},
		{
			name:    "external template not found",
			ext:     true,
			wantErr: fmt.Errorf(`the template "login.tmpl" does not exist`),
		},
		{
			name:     "external template happy path",
			ext:      true,
			basePath: "testBasePath",
			data: map[string]interface{}{
				"CSRFToken":            "testCSRFToken",
				"Challenge":            "testChalenge",
				"LoginURL":             "testLoginURL",
				"IsInvalidCredentials": true,
				"IsInternalError":      true,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tstDir := path.Join("testdata", t.Name())

			// Create the template renderer.
			cnf := Config{BasePath: tc.basePath}
			if tc.ext {
				cnf.Dir = tstDir
			} else {
				origin := intTmplsFS
				defer func() { intTmplsFS = origin }()
				intTmplsFS = http.Dir(tstDir)
			}
			r, err := NewHTMLRenderer(cnf)
			if err != nil {
				t.Fatalf("failed to create the template renderer: %s", err)
			}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			req.Header.Set(http.CanonicalHeaderKey("Accept-Language"), "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
			err = r.RenderTemplate(rr, req, "login.tmpl", tc.data)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("\ngot not errors\nwant error\n\t%s", tc.wantErr)
				}
				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("\ngot error:\n\t%s\nwant error\n\t%s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("\ngot error\n\t%s\nwant no errors", err)
			}
			f, err := os.Open(path.Join(tstDir, "golden.file"))
			if err != nil {
				t.Fatalf("failed to open golden file: %s", err)
			}
			fc, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read golden file: %s", err)
			}
			if got, want := rr.Body.String(), string(fc); got != want {
				t.Errorf("\nbody diff (-want +got):\n%s", diff.LineDiff(want, got))
			}
		})
	}
}

func TestHTMLRenderer_old_template(t *testing.T) {
	testCases := []struct {
		name     string
		ext      bool
		basePath string
		data     interface{}
		wantErr  error
	}{
		{
			name:    "internal template not found",
			wantErr: fmt.Errorf(`the template "login.tmpl" does not exist`),
		},
		{
			name:     "internal template happy path",
			basePath: "testBasePath",
			data: map[string]interface{}{
				"CSRFToken":            "testCSRFToken",
				"Challenge":            "testChalenge",
				"LoginURL":             "testLoginURL",
				"IsInvalidCredentials": true,
				"IsInternalError":      true,
			},
		},
		{
			name:    "external template not found",
			ext:     true,
			wantErr: fmt.Errorf(`the template "login.tmpl" does not exist`),
		},
		{
			name:     "external template happy path",
			ext:      true,
			basePath: "testBasePath",
			data: map[string]interface{}{
				"CSRFToken":            "testCSRFToken",
				"Challenge":            "testChalenge",
				"LoginURL":             "testLoginURL",
				"IsInvalidCredentials": true,
				"IsInternalError":      true,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tstDir := path.Join("testdata", t.Name())

			// Read the main template.
			var originMainT = mainT
			defer func() { mainT = originMainT }()
			f, err := os.Open(path.Join(tstDir, "main.tmpl"))
			if err != nil {
				t.Fatalf("failed to open main template: %s", err)
			}
			fc, err := ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read main template: %s", err)
			}
			mainT = string(fc)

			// Create the template renderer.
			cnf := Config{BasePath: tc.basePath}
			if tc.ext {
				cnf.Dir = tstDir
			} else {
				origin := intTmplsFS
				defer func() { intTmplsFS = origin }()
				intTmplsFS = http.Dir(tstDir)
			}
			r, err := NewHTMLRenderer(cnf)
			if err != nil {
				t.Fatalf("failed to create the template renderer: %s", err)
			}

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			req.Header.Set(http.CanonicalHeaderKey("Accept-Language"), "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
			err = r.RenderTemplate(rr, req, "login.tmpl", tc.data)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("\ngot not errors\nwant error\n\t%s", tc.wantErr)
				}
				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("\ngot error:\n\t%s\nwant error\n\t%s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("\ngot error\n\t%s\nwant no errors", err)
			}
			f, err = os.Open(path.Join(tstDir, "golden.file"))
			if err != nil {
				t.Fatalf("failed to open golden file: %s", err)
			}
			fc, err = ioutil.ReadAll(f)
			if err != nil {
				t.Fatalf("failed to read golden file: %s", err)
			}
			if got, want := rr.Body.String(), string(fc); got != want {
				t.Errorf("\nbody diff (-want +got):\n%s", diff.LineDiff(want, got))
			}
		})
	}
}

func TestStaticHandler(t *testing.T) {
	testCases := []struct {
		name       string
		ext        bool
		file       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "internal resource not found",
			file:       "not.found",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "internal resource happy path",
			file:       "test.file",
			wantStatus: http.StatusOK,
			wantBody:   "test",
		},
		{
			name:       "external resource not found",
			ext:        true,
			file:       "not.found",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "external resource happy path",
			ext:        true,
			file:       "test.file",
			wantStatus: http.StatusOK,
			wantBody:   "test",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tstDir := path.Join("testdata", t.Name())
			cnf := Config{}
			if tc.ext {
				cnf.Dir = tstDir
			} else {
				origin := intStaticFS
				defer func() { intStaticFS = origin }()
				intStaticFS = http.Dir(path.Join(tstDir, "static"))
			}

			r := httptest.NewRequest(http.MethodGet, "/static/"+tc.file, nil)
			rr := httptest.NewRecorder()

			router := routegroup.NewRouter()
			router.AddRoutes(NewStaticHandler(cnf), "/static")
			router.ServeHTTP(rr, r)

			if rr.Code != tc.wantStatus {
				t.Errorf("got status %d, want status %d", rr.Code, tc.wantStatus)
			}
			if tc.wantBody != "" {
				if got := rr.Body.String(); got != tc.wantBody {
					t.Errorf("got body %q, want body %q", got, tc.wantBody)
				}
			}
		})
	}
}
