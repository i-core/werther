# Copyright (c) JSC iCore.

# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.13-alpine AS build

ARG VERSION
ARG GOPROXY

WORKDIR /opt/build

RUN adduser -D -g '' appuser
RUN apk --update add ca-certificates
COPY go.mod .
COPY go.sum .
COPY cmd cmd
COPY internal internal
RUN env CGO_ENABLED=0 go install -ldflags="-w -s -X main.version=${VERSION}" ./...

FROM scratch AS final
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/werther /werther

USER appuser
ENTRYPOINT ["/werther"]
