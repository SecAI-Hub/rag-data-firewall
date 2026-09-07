FROM docker.io/library/golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rag-data-firewall .

FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN mkdir -p /etc/secure-ai/policy /var/lib/secure-ai/rag /var/lib/secure-ai/logs /run/secure-ai && \
    chown -R 65534:65534 /var/lib/secure-ai /run/secure-ai && \
    chmod 0700 /var/lib/secure-ai/rag /var/lib/secure-ai/logs /run/secure-ai
COPY policies/default-policy.yaml /etc/secure-ai/policy/rag-firewall.yaml
COPY --from=build /out/rag-data-firewall /usr/local/bin/rag-data-firewall
USER 65534:65534
ENV ALLOW_REMOTE_BIND=true
EXPOSE 8500
ENTRYPOINT ["rag-data-firewall"]
CMD ["serve", "-bind", "0.0.0.0:8500"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8500/health || exit 1
