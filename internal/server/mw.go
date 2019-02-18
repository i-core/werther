/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, February 2019
*/

package server

import (
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"go.uber.org/zap"
	"gopkg.i-core.ru/werther/internal/logger"
)

type traceResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *traceResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// logw returns a middleware that places a request's ID and logger to a request's context, and logs the request.
func logw(log *zap.SugaredLogger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				log = log.With("requestID", uuid.Must(uuid.NewV4()).String())
				ctx = logger.WithLogger(r.Context(), log)
			)
			log.Infow("New request", "method", r.Method, "url", r.URL.String())

			start := time.Now()
			tw := &traceResponseWriter{w, http.StatusOK}
			next.ServeHTTP(w, r.WithContext(ctx))

			log.Debugw("The request is handled", "httpStatus", tw.statusCode, "duration", time.Since(start))
		})
	}
}
