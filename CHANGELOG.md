# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2019-05-15
### Added
- Add gopkg.i-core.ru/logutil as a logger middleware.
- Add gopkg.i-core.ru/httputil as a HTTP router.
### Changed
- Move to Golang 1.12 when build the application in Docker.
- Update golangci-lint config.
- Update the copyright.
### Removed
- Remove the HTTP handler of Prometheus's metrics.

## [1.1.0] - 2019-05-15
### Added
- Add support of logout flow.

## [1.0.0] - 2019-02-18
### Added
- Add unit tests for server's logic.

### Changed
- The url /auth/login accepts the POST parameter login_challenge instead of challenge.
- The OIDC claim roles is enabled in the scope http://i-core.ru/claims/roles only.
- Use go.uber.org/zap without any facade.
