/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, July 2018
*/

package hydra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"gopkg.i-core.ru/werther/internal/oauth2"
)

type reqType string

const (
	login   reqType = "login"
	consent reqType = "consent"
)

func initiateRequest(typ reqType, hydraURL, challenge string) (*oauth2.ReqInfo, error) {
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/%s/%s", string(typ), challenge))
	if err != nil {
		return nil, err
	}
	u, err := parseURL(hydraURL)
	if err != nil {
		return nil, err
	}
	u = u.ResolveReference(ref)

	resp, err := http.Get(u.String())
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
	var ri oauth2.ReqInfo
	if err := json.Unmarshal(data, &ri); err != nil {
		return nil, err
	}
	return &ri, nil
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 302 {
		return nil
	}
	if resp.StatusCode == 404 {
		return oauth2.ErrChallengeNotFound
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	type errorResult struct {
		Message string `json:"error"`
	}
	var rs errorResult
	if err := json.Unmarshal(data, &rs); err != nil {
		return err
	}
	switch resp.StatusCode {
	case 401:
		return oauth2.ErrUnauthenticated
	case 409:
		return oauth2.ErrChallengeExpired
	default:
		return fmt.Errorf("bad HTTP status code %d", resp.StatusCode)
	}
}

func acceptRequest(typ reqType, hydraURL, challenge string, data interface{}) (string, error) {
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/%s/%s/accept", string(typ), challenge))
	if err != nil {
		return "", err
	}
	u, err := parseURL(hydraURL)
	if err != nil {
		return "", err
	}
	u = u.ResolveReference(ref)

	body, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	r, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(body))
	if err != nil {
		return "", err
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
	type result struct {
		RedirectTo string `json:"redirect_to"`
	}
	var rs result
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&rs); err != nil {
		return "", err
	}
	return rs.RedirectTo, nil
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
