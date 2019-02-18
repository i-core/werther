/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, February 2019
*/

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTraceResponseWriter(t *testing.T) {
	wantStatus := http.StatusBadRequest
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
	})
	r, err := http.NewRequest("GET", "http://foo.bar", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	tw := &traceResponseWriter{ResponseWriter: httptest.NewRecorder()}
	h.ServeHTTP(tw, r)
	if tw.statusCode != wantStatus {
		t.Errorf("invalid HTTP status code %d; want %d", tw.statusCode, wantStatus)
	}
}
