FROM golang:1.25-alpine AS builder

ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# No GOARCH pin: build for the host platform. OpenShift BuildConfig nodes are
# amd64 so cluster images are unchanged, while podman builds on ARM hosts
# (for example Apple Silicon) produce a native binary instead of an
# amd64 one that only runs under emulation. When building on one platform
# for another, pass --platform explicitly (for example
# `podman build --platform linux/amd64` before pushing to a cluster
# registry) rather than restoring a pin here.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /metering-service ./cmd

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.5

WORKDIR /
COPY --from=builder /metering-service /metering-service
USER 1001

ENTRYPOINT ["/metering-service"]
