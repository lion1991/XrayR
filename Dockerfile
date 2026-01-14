# Build go
# Build context should be the repo root that contains both `XrayR/` and `sing-box/`.
ARG GO_IMAGE=golang:1.25.3-alpine
ARG RUNTIME_IMAGE=alpine:latest
ARG GOPROXY=
ARG GOSUMDB=

FROM ${GO_IMAGE} AS builder
WORKDIR /app
COPY XrayR/ ./XrayR/
COPY sing-box/ ./sing-box/
WORKDIR /app/XrayR
ARG GOPROXY
ARG GOSUMDB
ENV CGO_ENABLED=0
ENV GOPROXY=${GOPROXY}
ENV GOSUMDB=${GOSUMDB}
RUN go mod download
RUN go build -v -o /app/bin/XrayR -trimpath -ldflags "-s -w -buildid="

# Release
FROM ${RUNTIME_IMAGE}
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/XrayR/
COPY --from=builder /app/bin/XrayR /usr/local/bin/XrayR

ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml"]
