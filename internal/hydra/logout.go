/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package hydra

import (
	"github.com/pkg/errors"
)

// LogoutReqDoer fetches information on the OAuth2 request and then accepts or rejects the requested logout process.
type LogoutReqDoer struct {
	hydraURL           string
	fakeTlsTermination bool
}

// NewLogoutReqDoer creates a LogoutRequest.
func NewLogoutReqDoer(hydraURL string, fakeTlsTermination bool) *LogoutReqDoer {
	return &LogoutReqDoer{hydraURL: hydraURL, fakeTlsTermination: fakeTlsTermination}
}

// InitiateRequest fetches information on the OAuth2 request.
func (lrd *LogoutReqDoer) InitiateRequest(challenge string) (*ReqInfo, error) {
	ri, err := initiateRequest(logout, lrd.hydraURL, lrd.fakeTlsTermination, challenge)
	return ri, errors.Wrap(err, "failed to initiate logout request")
}

// AcceptLogoutRequest accepts the requested logout process, and returns redirect URI.
func (lrd *LogoutReqDoer) AcceptLogoutRequest(challenge string) (string, error) {
	redirectURI, err := acceptRequest(logout, lrd.hydraURL, lrd.fakeTlsTermination, challenge, nil)
	return redirectURI, errors.Wrap(err, "failed to accept logout request")
}
