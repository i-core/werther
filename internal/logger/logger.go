/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, February 2019
*/

package logger

import (
	"context"

	"go.uber.org/zap"
)

type requestLogCtxKey int

// requestLogKey is a context's key to store a request's logger.
const requestLogKey requestLogCtxKey = iota

// FromContext returns a request's logger stored in a context.
func FromContext(ctx context.Context) *zap.SugaredLogger {
	v := ctx.Value(requestLogKey)
	if v == nil {
		return zap.NewNop().Sugar()
	}
	return v.(*zap.SugaredLogger)
}

// WithLogger returns context.Context with a logger's instance.
func WithLogger(ctx context.Context, log *zap.SugaredLogger) context.Context {
	return context.WithValue(ctx, requestLogKey, log)
}
