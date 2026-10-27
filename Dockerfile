# syntax=docker/dockerfile:1
#
# Build with golang:alpine, then ship only the static binary in a scratch image.
# The runtime has no shell, package manager, CA bundle, or tzdata. sb-render
# only reads mounted config files and serves HTTP, so nginx still owns TLS.

FROM golang:alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/sb-render ./cmd/sb-render

FROM scratch

COPY --from=build /out/sb-render /sb-render

# Numeric UID/GID; no /etc/passwd is needed in scratch.
USER 10001:10001
EXPOSE 8080

# The container binds 0.0.0.0 internally. Only safe when the published port is
# restricted to host loopback or a private network; nginx still authenticates.
ENTRYPOINT ["/sb-render"]
CMD ["--config","/config","--listen","0.0.0.0:8080","--allow-public"]
