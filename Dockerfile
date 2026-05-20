# syntax=docker/dockerfile:1.7

# ---- Stage 1: build the Go binary --------------------------------------------
ARG GO_IMAGE=golang:1.25.5-alpine
ARG RUNTIME_IMAGE=alpine:latest
ARG GOPROXY=
ARG GOSUMDB=

FROM ${GO_IMAGE} AS builder
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
ARG GOPROXY
ARG GOSUMDB
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go build -v -o /out/XrayR -trimpath -ldflags "-s -w -buildid="

# ---- Stage 2: runtime --------------------------------------------------------
FROM ${RUNTIME_IMAGE}
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/XrayR/
COPY --from=builder /out/XrayR /usr/local/bin/XrayR
ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml"]
