/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential
*/

package hydra

import (
	"github.com/pkg/errors"
)

// ConsentReqDoer fetches information on the OAuth2 request and then accept or reject the requested authentication process.
type ConsentReqDoer struct {
	hydraURL    string
	rememberFor int
}

// NewConsentReqDoer creates a ConsentRequest.
func NewConsentReqDoer(hydraURL string, rememberFor int) *ConsentReqDoer {
	return &ConsentReqDoer{hydraURL: hydraURL, rememberFor: rememberFor}
}

// InitiateRequest fetches information on the OAuth2 request.
func (crd *ConsentReqDoer) InitiateRequest(challenge string) (*ReqInfo, error) {
	ri, err := initiateRequest(consent, crd.hydraURL, challenge)
	return ri, errors.Wrap(err, "failed to initiate consent request")
}

// AcceptConsentRequest accepts the requested authentication process, and returns redirect URI.
func (crd *ConsentReqDoer) AcceptConsentRequest(challenge string, remember bool, grantScope []string, idToken interface{}) (string, error) {
	type session struct {
		IDToken interface{} `json:"id_token,omitempty"`
	}
	data := struct {
		GrantScope  []string `json:"grant_scope"`
		Remember    bool     `json:"remember"`
		RememberFor int      `json:"remember_for"`
		Session     session  `json:"session,omitempty"`
	}{
		GrantScope:  grantScope,
		Remember:    remember,
		RememberFor: crd.rememberFor,
		Session: session{
			IDToken: idToken,
		},
	}
	redirectURI, err := acceptRequest(consent, crd.hydraURL, challenge, data)
	return redirectURI, errors.Wrap(err, "failed to accept consent request")
}
