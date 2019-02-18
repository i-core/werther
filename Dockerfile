# Copyright (C) JSC iCore - All Rights Reserved
#
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential
#
# Written by Konstantin Lepa <klepa@i-core.ru>, July 2018

FROM golang:1.11-alpine AS build

ARG VERSION
ARG GOPROXY

WORKDIR /opt/build

RUN adduser -D -g '' appuser
RUN apk --update add ca-certificates
COPY go.mod .
COPY go.sum .
COPY cmd cmd
COPY internal internal
RUN env CGO_ENABLED=0 go install -ldflags="-w -s -X gopkg.i-core.ru/werther/internal/server.Version=${VERSION}" ./...

FROM scratch AS final
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/werther /werther

USER appuser
ENTRYPOINT ["/werther"]
