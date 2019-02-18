# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2019-02-18
### Added
- Add unit tests for server's logic.

### Changed
- The url /auth/login accepts the POST parameter login_challenge instead of challenge.
- The OIDC claim roles is enabled in the scope http://i-core.ru/claims/roles only.
- Use go.uber.org/zap without any facade.
