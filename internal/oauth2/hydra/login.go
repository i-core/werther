/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, July 2018
*/

package hydra

import (
	"github.com/pkg/errors"
	"gopkg.i-core.ru/werther/internal/oauth2"
)

// LoginReqDoer fetches information on the OAuth2 request and then accept or reject the requested authentication process.
type LoginReqDoer struct {
	hydraURL string
}

// NewLoginRequest creates a LoginRequest.
func NewLoginReqDoer(hydraURL string) *LoginReqDoer {
	return &LoginReqDoer{hydraURL: hydraURL}
}

// InitiateRequest fetches information on the OAuth2 request.
func (lrd *LoginReqDoer) InitiateRequest(challenge string) (*oauth2.ReqInfo, error) {
	ri, err := initiateRequest(login, lrd.hydraURL, challenge)
	return ri, errors.Wrap(err, "failed to initiate login request")
}

// Accept accepts the requested authentication process, and returns redirect URI.
func (lrd *LoginReqDoer) AcceptLoginRequest(challenge string, remember bool, rememberFor int, subject string) (string, error) {
	data := struct {
		Remember    bool   `json:"remember"`
		RememberFor int    `json:"remember_for"`
		Subject     string `json:"subject"`
	}{
		Remember:    remember,
		RememberFor: rememberFor,
		Subject:     subject,
	}
	redirectURI, err := acceptRequest(login, lrd.hydraURL, challenge, data)
	return redirectURI, errors.Wrap(err, "failed to accept login request")
}
