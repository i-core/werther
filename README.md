[![GoDoc](https://godoc.das.i-core.ru/gopkg.i-core.ru/werther?status.svg)](https://godoc.das.i-core.ru/gopkg.i-core.ru/werther)

# Werther

Werther is an identity provider for ORY Hydra that is an OAuth2 provider.

**Important!**
**The current version is compatible with ORY Hydra v1.0.0-rc.12 or higher.**

## Build
```
go install ./...
```

## Development

Assume that your IP is set as $MY_HOST. The instruction will use 4444 TCP port for OAuth2 Provider Hydra,
3000 TCP port for Login Provider Werther, and 8080 TCP port for a callback. Tokens will be expired in ten minutes.

1. Create a network:
    ```
    docker network create hydra-net
    ```

2. Run ORY Hydra:
    ```
    docker run --network hydra-net -d --restart always --name hydra                                          \
        -p 4444:4444                                                                                         \
        -p 4445:4445                                                                                         \
        -e OAUTH2_EXPOSE_INTERNAL_ERRORS=true                                                                \
        -e LOG_LEVEL=debug                                                                                   \
        -e TTL_ACCESS_TOKEN=10m                                                                              \
        -e TTL_ID_TOKEN=10m                                                                                  \
        -e SERVE_PUBLIC_CORS_ENABLED=true                                                                    \
        -e SERVE_PUBLIC_CORS_ALLOWED_ORIGINS=http://$MY_HOST:8080                                            \
        -e SERVE_PUBLIC_CORS_ALLOW_CREDENTIALS=true                                                          \
        -e WEBFINGER_OIDC_DISCOVERY_SUPPORTED_SCOPES=profile,email,phone                                     \
        -e WEBFINGER_OIDC_DISCOVERY_SUPPORTED_CLAIMS=name,family_name,given_name,nickname,email,phone_number \
        -e URLS_SELF_ISSUER=http://localhost:4444                                                            \
        -e URLS_SELF_PUBLIC=http://localhost:4444                                                            \
        -e URLS_LOGIN=http://$MY_HOST:3000/auth/login                                                        \
        -e URLS_CONSENT=http://$MY_HOST:3000/auth/consent                                                    \
        -e URLS_LOGOUT=http://$MY_HOST:3000/auth/logout                                                      \
        -e DSN=memory                                                                                        \
        oryd/hydra:v1.0.0-rc.12 serve all --dangerous-force-http
    ```

    You can learn additional properties with help command:
    ```
    docker run -it --rm oryd/hydra:v1.0.0-rc.12 serve --help
    ```

3. Register a client:
    ```
    docker run -it --rm --network hydra-net                                 \
          -e HYDRA_ADMIN_URL=http://hydra:4445                              \
          oryd/hydra:$HYDRA_VERSION clients create                          \
          --skip-tls-verify                                                 \
          --id test-client                                                  \
          --secret test-secret                                              \
          --response-types id_token,token,"id_token token"                  \
          --grant-types implicit                                            \
          --scope openid,profile,email                                      \
          --callbacks http://$MY_HOST:8080                                  \
          --post-logout-callbacks http://$MY_HOST:8080/post-logout-callback
    ```

4. Run Werther:
    ```
    docker run --network hydra-net -d --restart always --name werther -p 3000:8080      \
          -e WERTHER_IDENTP_HYDRA_URL=http://hydra:4445                                  \
          -e WERTHER_LDAP_ENDPOINTS=icdc0.icore.local:389,icdc1.icore.local:389         \
          -e WERTHER_LDAP_BINDDN=<BINDDN>                                               \
          -e WERTHER_LDAP_BINDPW=<BINDDN_PASSWORD>                                      \
          -e WERTHER_LDAP_BASEDN="DC=icore,DC=local"                                    \
          -e WERTHER_LDAP_ROLE_BASEDN="OU=AppRoles,OU=Domain Groups,DC=icore,DC=local"  \
          hub.das.i-core.ru/p/base-werther
    ```

    For all options see option help:
    ```
    docker run -it --rm hub.das.i-core.ru/p/base-werther -help
    ```

5. Start an authentication process in a browser to get an access token:
    ```
    open http://$MY_HOST:4444/oauth2/auth?client_id=test-client&response_type=token&scope=openid%20profile%20email&state=12345678
    ```
6. Start an authentication process in a browser to get an access token and id token:
    ```
    open http://$MY_HOST:4444/oauth2/auth?client_id=test-client&response_type=id_token%20token&scope=openid%20profile%20email&state=12345678&nonce=87654321
    ```

7. Get user info:
    ```
    http get "http://$MY_HOST:4444/userinfo" "Authorization: Bearer <ACCESS_TOKEN>"
    ```

    For example, you can get the next output:
    ```
    HTTP/1.1 200 OK
    Content-Length: 218
    Content-Type: application/json
    Date: Tue, 31 Jul 2018 17:17:51 GMT
    Vary: Origin

    {
        "email": "klepa@i-core.ru",
        "family_name": "Lepa",
        "given_name": "Konstantin",
        "http://i-core.ru/claims/roles": {
            "HeraldTest1": [
                "user"
            ]
        },
        "name": "Konstantin Lepa",
        "sub": "CN=Konstantin Lepa,OU=Domain Users,DC=icore,DC=local"
    }
    ```

    Look for details in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter).

8. Re-get a token by httpie:
    ```
    http --session u1 -F -v get \
          "http://$MY_HOST:4444/oauth2/auth?client_id=test-client&response_type=token&scope=openid%20profile&state=12345678&prompt=none" \
          "Cookie:<COOKIES_FROM_WERTHER_DOMAIN>"
    ```

9. Delete a user's session from a browser:
    ```
    open "http://$MY_HOST:4444/oauth2/auth/sessions/login/revoke"
    ```

10. Log a user out from a browser:
    ```
    open http://$MY_HOST:4444/oauth2/sessions/logout?id_token_hint=<id_token>&post_logout_redirect_uri=http://$MY_HOST:8080/post-logout-callback&state=87654321
    ```
    After a successful logout, a user will be redirected to the page "http://$MY_HOST:8080/post-logout-callback?state=87654321".


11. (Optional) Sniff TCP packets between Hydra and Werther
    ```
    docker run -it --rm --net=container:hydra nicolaka/netshoot tcpdump -i eth0 -A -nn port 4444
    ```

