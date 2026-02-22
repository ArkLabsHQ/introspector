# Gvproxy container for forwarding HTTP ports into the enclave.
FROM golang:1.25.5 AS builder

ARG GVPROXY_VERSION=v0.7.4
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go install github.com/containers/gvisor-tap-vsock/cmd/gvproxy@${GVPROXY_VERSION}

FROM alpine:3.20

RUN apk update && apk upgrade
RUN apk --no-cache add curl

WORKDIR /app

COPY --from=builder /go/bin/gvproxy /app/gvproxy
COPY enclave/gvproxy/start.sh /app/start.sh

CMD ["/app/start.sh"]
