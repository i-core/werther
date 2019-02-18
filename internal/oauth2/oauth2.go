/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, February 2019
*/

package oauth2

import "errors"

var (
	// ErrUnauthenticated is an error that happens when authentication is failed.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrChallengeNotFound is an error that happens when an unknown challenge is used.
	ErrChallengeNotFound = errors.New("challenge not found")
	// ErrChallengeExpired is an error that happens when a challenge is already used.
	ErrChallengeExpired = errors.New("challenge expired")
)

// ReqInfo contains information on an ongoing login or consent request.
type ReqInfo struct {
	Challenge       string   `json:"challenge"`
	RequestedScopes []string `json:"requested_scope"`
	Skip            bool     `json:"skip"`
	Subject         string   `json:"subject"`
}
