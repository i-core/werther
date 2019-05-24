package stat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/i-core/routegroup"
)

func TestHealthHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	h := newHealthHandler()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://example.org", nil))
	testResp(t, rr, http.StatusOK, "application/json", map[string]interface{}{"status": "ok"})
}

func TestVersionHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	h := newVersionHandler("test-version")
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://example.org", nil))
	testResp(t, rr, http.StatusOK, "application/json", map[string]interface{}{"version": "test-version"})
}

func TestStatHandler(t *testing.T) {
	var (
		rr     *httptest.ResponseRecorder
		router = routegroup.NewRouter()
	)
	router.AddRoutes(NewHandler("test-version"), "/stat")

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/stat/health/alive", nil))
	testResp(t, rr, http.StatusOK, "application/json", map[string]interface{}{"status": "ok"})

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/stat/health/ready", nil))
	testResp(t, rr, http.StatusOK, "application/json", map[string]interface{}{"status": "ok"})

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/stat/version", nil))
	testResp(t, rr, http.StatusOK, "application/json", map[string]interface{}{"version": "test-version"})
}

func testResp(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, wantMime string, wantBody interface{}) {
	if rr.Code != wantStatus {
		t.Errorf("got status %d, want status %d", rr.Code, wantStatus)
	}

	if gotMime := rr.Header().Get("Content-Type"); gotMime != wantMime {
		t.Errorf("got content type %q, want content type %q", gotMime, wantMime)
	}

	var gotBody interface{}
	if err := json.NewDecoder(rr.Body).Decode(&gotBody); err != nil {
		t.Fatalf("failed to decode the request body: %s", err)
	}

	if !reflect.DeepEqual(gotBody, wantBody) {
		t.Errorf("got body %#v, want body %#v", gotBody, wantBody)
	}
}
