FROM golang:1.24 AS builder
ARG TARGETARCH
COPY . /go/src/github.com/unravel-data/tty2web
WORKDIR /go/src/github.com/unravel-data/tty2web
RUN go build -o /go/bin/tty2web -v -trimpath -ldflags "-w -s" .

FROM rockylinux/rockylinux:10

ARG TARGETARCH

LABEL org.opencontainers.image.vendor="Unravel Data, Inc." \
      org.opencontainers.image.authors="Unravel Data, Inc." \
      org.opencontainers.image.title="tty2web"

COPY --from=builder /go/bin/tty2web /usr/local/bin/tty2web

ENV TERM=xterm-256color

RUN dnf install -y nano procps-ng \
    && dnf clean all \
    && rm -rf /var/cache/dnf/*

# Install kubectl and yq
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/ \
    && curl -LO "https://github.com/mikefarah/yq/releases/download/v4.45.4/yq_linux_${TARGETARCH}" \
    && chmod +x yq_linux_${TARGETARCH} \
    && mv yq_linux_${TARGETARCH} /usr/local/bin/yq

ENTRYPOINT ["tty2web"]