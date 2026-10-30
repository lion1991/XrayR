# syntax=docker/dockerfile:1.7

# ---- Stage 1: build the Go binary --------------------------------------------
ARG GO_IMAGE=golang:1.26-alpine
ARG RUNTIME_IMAGE=alpine:latest
ARG GOPROXY=
ARG GOSUMDB=

FROM ${GO_IMAGE} AS builder
WORKDIR /src
RUN apk add --no-cache git openssh-client
ARG GOPROXY
ARG GOSUMDB
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}
ENV GOPRIVATE=git.wrlog.cn
ENV CGO_ENABLED=0
# wkernel is a private repository on git.wrlog.cn, reached over ssh on port 2222.
COPY release/known_hosts /root/.ssh/known_hosts
RUN git config --global url."ssh://git@git.wrlog.cn:2222/".insteadOf "https://git.wrlog.cn/"
COPY . .
# Download and build in one step, with the module cache in a cache mount: CI
# exports every layer to the Actions cache of a public repository, so the
# wkernel source must never land in one. The deploy key comes in through the
# forwarded ssh agent and is not written anywhere either.
RUN --mount=type=ssh,required=true \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /out/XrayR -trimpath -tags "$(cat release/build_tags)" -ldflags "-s -w -buildid="

# ---- Stage 2: runtime --------------------------------------------------------
FROM ${RUNTIME_IMAGE}
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/XrayR/
COPY --from=builder /out/XrayR /usr/local/bin/XrayR
ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml"]
