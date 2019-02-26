FROM golang:1.11-alpine AS builder

WORKDIR /go/src/github.com/hellofresh/janus
COPY . .
RUN GO_ENABLED=0 GOOS=linux go build -o /janus main.go

# ---

FROM alpine:3.8

COPY --from=builder /janus /usr/local/bin/janus

RUN true \
 && apk add --no-cache ca-certificates \
 && mkdir -p /etc/janus/apis \
 && mkdir -p /etc/janus/auth

# FIXME respect passed config
#HEALTHCHECK --interval=5s --timeout=5s --retries=3 CMD curl -f http://localhost:8081/status || exit 1

ENTRYPOINT ["janus", "start"]
