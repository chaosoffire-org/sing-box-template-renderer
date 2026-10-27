# Multi-stage build for sb-render.
#
# The runtime image contains only the static binary, CA roots, and an empty
# /config mount point. Real users/, modes/, and templates/ are mounted at run
# time and never baked into the image.
#
# SECURITY: the runtime CMD passes --allow-public because the container binds
# 0.0.0.0 internally. That is only safe when the published port is reachable
# solely from host loopback or a private network, and nginx still terminates
# TLS and performs Basic Auth in front of it. Never publish this port directly
# to the internet.

FROM golang:1.27 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/sb-render ./cmd/sb-render

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
	&& addgroup -g 10001 -S sb-render \
	&& adduser -u 10001 -S -G sb-render -h /nonexistent -s /sbin/nologin sb-render \
	&& mkdir -p /config \
	&& chown 10001:10001 /config

COPY --from=build /out/sb-render /usr/local/bin/sb-render

USER 10001:10001
EXPOSE 8080

# --allow-public is only safe when the container port is published to host
# loopback or a private network; nginx still owns authentication. The Go
# service must never be exposed directly.
ENTRYPOINT ["/usr/local/bin/sb-render"]
CMD ["--config","/config","--listen","0.0.0.0:8080","--allow-public"]
