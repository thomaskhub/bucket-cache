# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS build
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/thomaskhub/yocto-cache-proxy/internal/version.Version=$VERSION -X github.com/thomaskhub/yocto-cache-proxy/internal/version.Commit=$COMMIT" \
      -o /out/yproxy ./cmd/yproxy

# git is needed at runtime for the git mirror (it runs as a separate process,
# see NFR-LIC). Debian ships its license texts under /usr/share/doc.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /git/.home --shell /usr/sbin/nologin yproxy \
 && mkdir -p /data /cache /git /etc/proxy \
 && chown 10001:10001 /data /cache /git
COPY --from=build /out/yproxy /usr/local/bin/yproxy
COPY THIRD_PARTY_LICENSES* /usr/share/doc/yproxy/
COPY LICENSE /usr/share/doc/yproxy/LICENSE
USER 10001:10001
ENV PROXY_CONFIG=/etc/proxy/config.yaml HOME=/git/.home
VOLUME ["/data", "/cache", "/git"]
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/local/bin/yproxy", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/yproxy"]
CMD ["serve"]
