# Werther <sup>[1](#myfootnote1)</sup>

[![GoDoc][doc-img]][doc] [![Build Status][build-img]][build] [![codecov][codecov-img]][codecov]

Werther is an Identity Provider for [ORY Hydra][hydra] over [LDAP][ldap].
It implements [Login And Consent Flow][hydra-login-consent] and provides basic UI.

![screenshot](.github/media/screenshot.gif)

**Features**
- Support [Active Directory][ad];
- Mapping LDAP attributes to OpenID Connect claims;
- Mapping LDAP groups to user roles;
- OAuth 2.0 scopes;
- Caching users roles;
- UI customization.

**Limitations**
- Werther grants all requested permissions to a client without displaying the consent page;
- Werther confirms a logout request without displaying the logout confirmation page.

**Requirements**

ORY Hydra v1.0.0-rc.12 or higher.

**Table of Contents**
<!-- To generate the table use the command "npx doctoc --maxlevel 2 README.md" -->
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Installing](#installing)
- [Usage](#usage)
- [Configuration](#configuration)
- [User roles](#user-roles)
- [UI customization](#ui-customization)
- [Resources](#resources)
- [Footnotes](#footnotes)
- [Contributing](#contributing)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installing

### From Docker

```bash
docker pull icoreru/werter
```

### From sources

```bash
go install ./...
```

## Usage

1. Create a network:
    ```
    docker network create hydra-net
    ```

2. Run ORY Hydra:
    ```
    docker run --network hydra-net -d --restart always --name hydra                                          \
        -p 4444:4444                                                                                         \
        -p 4445:4445                                                                                         \
        -e URLS_SELF_ISSUER=http://localhost:4444                                                            \
        -e URLS_SELF_PUBLIC=http://localhost:4444                                                            \
        -e URLS_LOGIN=http://localhost:8080/auth/login                                                       \
        -e URLS_CONSENT=http://localhost:8080/auth/consent                                                   \
        -e URLS_LOGOUT=http://localhost:8080/auth/logout                                                     \
        -e WEBFINGER_OIDC_DISCOVERY_SUPPORTED_SCOPES=profile,email,phone                                     \
        -e WEBFINGER_OIDC_DISCOVERY_SUPPORTED_CLAIMS=name,family_name,given_name,nickname,email,phone_number \
        -e DSN=memory                                                                                        \
        oryd/hydra:v1.0.0-rc.12 serve all
    ```

    Look for details in [ORY Hydra Configuration][hydra-doc-config] and [ORY Hydra Documentation][hydra-doc].

3. Run Werther:
    ```
    docker run --network hydra-net -d --restart always --name werther                    \
          -p 8080:8080                                                                   \
          -e WERTHER_IDENTP_HYDRA_URL=http://hydra:4445                                  \
          -e WERTHER_LDAP_ENDPOINTS=icdc0.example.local:389,icdc1.example.local:389      \
          -e WERTHER_LDAP_BINDDN=<BINDDN>                                                \
          -e WERTHER_LDAP_BINDPW=<BINDDN_PASSWORD>                                       \
          -e WERTHER_LDAP_BASEDN="DC=example,DC=local"                                   \
          -e WERTHER_LDAP_ROLE_BASEDN="OU=AppRoles,OU=Domain Groups,DC=example,DC=local" \
          icoreru/werther
    ```

## Configuration

The application is configured via environment variables.
Names of the environment variables starts with prefix `WERTHER_`.
See a list of the environment variables using the command:

```
werther -h
```

## User roles

In LDAP user's roles are groups in which a user is a member.

The environment variable `WERTHER_LDAP_ROLE_DN` is a DN for searching roles.

For example, create an OU that repserents an application, and then in the created OU
create groups that represent application's roles:

```
DC=local
|-- OU=Domain Groups
    |-- OU=AppRoles
        |-- OU=App1
            |-- CN=app1_role1 (objectClass="group", description="role1")
            |-- CN=app1_role2 (objectClass="group", description="role2")
```

Run Werther with the environment variable `WERTHER_LDAP_ROLE_DN`
that equals to `OU=AppRoles,OU=Domain Groups,DC=local`.

In the above example Werther returns user's roles as a value
of the user role's claim `https://github.com/i-core/werther/claims/roles`.

```json
{
    "https://github.com/i-core/werther/claims/roles": {
        "App1": ["role1", "role2"],
    }
}
```

To customize the roles claim's name you should set a value of the environment variable `WERTHER_LDAP_ROLE_CLAIM`.
For more details about claims naming see [OpenID Connect Core 1.0][oidc-spec-additional-claims].

**NB** There are cases when we need to create several roles with the same name in LDAP.
For example, when we want to configure multiple applications or several environments for the same application.

```
DC=local
|-- OU=Domain Groups
    |-- OU=AppRoles
        |-- OU=Test
            |-- OU=App1
                |-- CN=test_app1_role1 (objectClass="group", description="role1")
                |-- CN=test_app1_role2 (objectClass="group", description="role2")
            |-- OU=App2
                |-- CN=test_app2_role1 (objectClass="group",description-"role1")
                |-- CN=test_app2_role2 (objectClass="group",description-"role2")
        |-- OU=Dev
            |-- OU=App1
                |-- CN=dev_app1_role1 (objectClass="group", description="role1")
                |-- CN=dev_app1_role3 (objectClass="group", description="role3")
            |-- OU=App2
                |-- CN=dev_app2_role1 (objectClass="group",description-"role1")
                |-- CN=dev_app2_role4 (objectClass="group",description-"role4")
```

Active Directory requires unique CNs in a domain. But in Active Directory
creating groups with the same CN in different OUs is difficult.
Because of it, Werther uses a LDAP attribute as a role's name instead of CN.
A name of a LDAP attribute is specified using the environment variable `WERTHER_LDAP_ROLE_ATTR`,
and has the default value `description`.

In the above example, Werther returns a response that contains the next roles:
* when the environment variable `WERTHER_LDAP_ROLE_DN` equals to `OU=Test,OU=AppRoles,OU=Domain Groups,DC=local`:
    ```json
    {
        "https://github.com/i-core/werther/claims/roles": {
            "App1": ["role1", "role2"],
            "App2": ["role1", "role2"]
        }
    }
    ```
* when the environment variable `WERTHER_LDAP_ROLE_DN` equals to `OU=Dev,OU=AppRoles,OU=Domain Groups,DC=local`:
    ```json
    {
        "https://github.com/i-core/werther/claims/roles": {
            "App1": ["role1", "role3"],
            "App2": ["role1", "role4"]
        }
    }
    ```

## UI customization

Werther uses the Go templates to render UI pages.
To customize the UI you should create a directory that contains UI pages' templates.
After that you should set the directory path to the environment variable `WERTHER_WEB_DIR`:

```bash
docker run --network hydra-net -d --restart always --name werther                      \
        -p 8080:8080                                                                   \
        -v /opt/werther/web:/path/to/custom-login-page/dir                             \
        -e WERTHER_IDENTP_HYDRA_URL=http://hydra:4445                                  \
        -e WERTHER_LDAP_ENDPOINTS=icdc0.example.local:389,icdc1.example.local:389      \
        -e WERTHER_LDAP_BINDDN=<BINDDN>                                                \
        -e WERTHER_LDAP_BINDPW=<BINDDN_PASSWORD>                                       \
        -e WERTHER_LDAP_BASEDN="DC=example,DC=local"                                   \
        -e WERTHER_LDAP_ROLE_BASEDN="OU=AppRoles,OU=Domain Groups,DC=example,DC=local" \
        -e WERTHER_WEB_DIR=/opt/werther/web
        icoreru/werther
```

### Custom login page

A login page's template should contains blocks `title`, `style`, `script`, `content`.
Each block has access to data that is an object with the next properties:
- `CSRFToken` (string) - a CSRF token;
- `Challenge` (string) - a login challenge ID;
- `LoginURL` (string) - an endpoint that finishes the login process;
- `IsInvalidCredentials` (bool) - specifies that a user types an invalid username or password;
- `IsInternalError` (bool) specifies that an internal server error happens when finishing the login process.

When a login page's template contains static resources (like styles, scripts, and images)
they must be placed in a subdirectory called `static`.

For a full example of a login page's template see [source code](internal/web/templates).

## Resources

- [Introduction to ORY Hydra, OAuth 2.0, and OpenID Connect][hydra-doc];
- [ORY Hydra: Integrating with (existing) User Management][hydra-login-consent];
- [Official User Login & Consent Example](https://github.com/ory/hydra-login-consent-node);
- [OpenID Connect Core 1.0][oidc-spec-core];
- [OpenID Connect Session Management 1.0][oidc-spec-session];
- [OpenID Connect Front-Channel Logout 1.0][oidc-spec-front-channel-logout];
- [OpenID Connect Back-Channel Logout 1.0][oidc-spec-back-channel-logout].

## Footnotes

1. <a name="myfootnote1"></a> Werther is named after robot Werther from [Guest from the Future](https://en.wikipedia.org/wiki/Guest_from_the_Future).

## Contributing

Thanks for your interest in contributing to this project.
Get started with our [Contributing Guide][contrib].

## License

The code in this project is licensed under [MIT license][license].

[doc-img]: https://godoc.org/github.com/i-core/werther?status.svg
[doc]: https://godoc.org/github.com/i-core/werther

[build-img]: https://travis-ci.com/i-core/werther.svg?branch=master
[build]: https://travis-ci.com/i-core/werther

[codecov-img]: https://codecov.io/gh/i-core/werther/branch/master/graph/badge.svg
[codecov]: https://codecov.io/gh/i-core/werther

[contrib]: https://github.com/i-core/.github/blob/master/CONTRIBUTING.md
[license]: LICENSE

[ldap]: https://ldap.com/
[ad]: https://docs.microsoft.com/ru-ru/windows/desktop/AD/active-directory-domain-services

[hydra]: https://www.ory.sh/
[hydra-doc]: https://www.ory.sh/docs/hydra/
[hydra-login-consent]: https://www.ory.sh/docs/hydra/oauth2
[hydra-doc-config]: https://www.ory.sh/docs/hydra/configuration

[oidc-spec-core]: https://openid.net/specs/openid-connect-core-1_0.html
[oidc-spec-additional-claims]: https://openid.net/specs/openid-connect-core-1_0.html#AdditionalClaims
[oidc-spec-session]: https://openid.net/specs/openid-connect-session-1_0.html
[oidc-spec-front-channel-logout]: https://openid.net/specs/openid-connect-frontchannel-1_0.html
[oidc-spec-back-channel-logout]: https://openid.net/specs/openid-connect-backchannel-1_0.html