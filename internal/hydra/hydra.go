/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package hydra

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

var (
	// ErrChallengeMissed is an error that happens when a challenge is missed.
	ErrChallengeMissed = errors.New("challenge missed")
	// ErrUnauthenticated is an error that happens when authentication is failed.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrChallengeNotFound is an error that happens when an unknown challenge is used.
	ErrChallengeNotFound = errors.New("challenge not found")
	// ErrChallengeExpired is an error that happens when a challenge is already used.
	ErrChallengeExpired = errors.New("challenge expired")
)

type reqType string

const (
	login   reqType = "login"
	consent reqType = "consent"
	logout  reqType = "logout"
)

// ReqInfo contains information on an ongoing login or consent request.
type ReqInfo struct {
	Challenge       string   `json:"challenge"`
	RequestedScopes []string `json:"requested_scope"`
	Skip            bool     `json:"skip"`
	Subject         string   `json:"subject"`
}

func initiateRequest(typ reqType, hydraURL string, fakeTLSTermination bool, challenge string) (*ReqInfo, error) {
	if challenge == "" {
		return nil, ErrChallengeMissed
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/%[1]s?%[1]s_challenge=%s", string(typ), challenge))
	if err != nil {
		return nil, err
	}
	u, err := parseURL(hydraURL)
	if err != nil {
		return nil, err
	}
	u = u.ResolveReference(ref)

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if fakeTLSTermination {
		req.Header.Add("X-Forwarded-Proto", "https")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if err = checkResponse(resp); err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var ri ReqInfo
	if err := json.Unmarshal(data, &ri); err != nil {
		return nil, err
	}
	return &ri, nil
}

func acceptRequest(typ reqType, hydraURL string, fakeTLSTermination bool, challenge string, data interface{}) (string, error) {
	if challenge == "" {
		return "", ErrChallengeMissed
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/%[1]s/accept?%[1]s_challenge=%s", string(typ), challenge))
	if err != nil {
		return "", err
	}
	u, err := parseURL(hydraURL)
	if err != nil {
		return "", err
	}
	u = u.ResolveReference(ref)

	var body []byte
	if data != nil {
		if body, err = json.Marshal(data); err != nil {
			return "", err
		}
	}

	r, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	if fakeTLSTermination {
		r.Header.Add("X-Forwarded-Proto", "https")
	}

	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := checkResponse(resp); err != nil {
		return "", err
	}
	var rs struct {
		RedirectTo string `json:"redirect_to"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&rs); err != nil {
		return "", err
	}
	return rs.RedirectTo, nil
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 302 {
		return nil
	}

	switch resp.StatusCode {
	case 401:
		return ErrUnauthenticated
	case 404:
		return ErrChallengeNotFound
	case 409:
		return ErrChallengeExpired
	default:
		var rs struct {
			Message string `json:"error"`
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &rs); err != nil {
			return err
		}
		return fmt.Errorf("bad HTTP status code %d with message %q", resp.StatusCode, rs.Message)
	}
}

func parseURL(s string) (*url.URL, error) {
	if len(s) > 0 && s[len(s)-1] != '/' {
		s += "/"
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return u, nil
}
