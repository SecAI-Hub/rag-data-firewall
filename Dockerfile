FROM docker.io/library/golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/rag-data-firewall .

FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
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
