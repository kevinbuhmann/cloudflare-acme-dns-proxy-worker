# cloudflare-acme-dns-proxy-worker

Proxy worker to allow caddy-dns/cloudflare / libdns/cloudflare to solve
ACME DNS-01 TLS challenges without access to entire DNS zone

## The Problem

Cloudflare does not provide the ability to generate an API token with
permissions for a subset of DNS records within a zone, and I didn't want
to give my server an API token with full-access to my domain's DNS records
or pass such a token to an ACME client.

## The Solution

Cloudflare provides free compute workers, so you can host a proxy of
Cloudflare's API on Cloudflare itself and only a subset of DNS operations.
That's what this project does. It allows valid ACME DNS-01 TLS challenge
operations and denies all other actions.

## Deployment

1. `git clone https://github.com/kevinbuhmann/cloudflare-acme-dns-proxy-worker.git`
2. `npm install`
3. `npm deploy`

Wrangler (Cloudflare's CLI) will create a worker named `acme-dns-proxy-worker` in
your account. You will then need to log into the Cloudflare dashboard and set the
secrets:

- `PROXY_SECRET`: auth token for your worker
- `CLOUDFLARE_API_TOKEN`: a real Cloudflare API token with access to edit your zone
- `ZONE_ID`: your zone id
- `ZONE_NAME`: your zone name
- `ALLOWED_CHALLENGE_NAME`: allowed ACME DNS-01 challenge record name

Note: Due to pattern validation in caddy-dns/cloudflare, your `PROXY_SECRET` must
match the Cloudflare API token format. You can generate one using the following:

```sh
printf 'cfat_%s\n' "$(openssl rand -base64 36 | tr '+/' '-_' | tr -d '=')"
```

## Usage

Build Caddy with a small patch to replace the Cloudflare API url:

```Dockerfile
FROM caddy:2-builder AS builder

ARG CLOUDFLARE_API_URL=https://api.cloudflare.com/client/v4

# Clone and patch the libdns Cloudflare implementation.
RUN git clone https://github.com/libdns/cloudflare.git /tmp/libdns-cloudflare

RUN sed -i \
    's|https://api.cloudflare.com/client/v4|'"$CLOUDFLARE_API_URL"'|g' \
    /tmp/libdns-cloudflare/client.go

# Build Caddy, replacing the transitive libdns dependency.
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/libdns/cloudflare=/tmp/libdns-cloudflare

FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

```yaml
# minimal docker-compose.yaml file

services:
  caddy:
    build:
      context: .
      args:
        CLOUDFLARE_API_URL: ${CLOUDFLARE_API_URL}
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./caddy-data:/data
      - ./caddy-config:/config
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
    environment:
      BASE_DOMAIN: ${BASE_DOMAIN}
      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}
```

```sh
# the interpolation variables

CLOUDFLARE_API_URL=https://acme-dns-proxy-worker.YOUR_WORKER_SUBDOMAIN.workers.dev/client/v4
CLOUDFLARE_API_TOKEN=YOUR_PROXY_SECRET
```

And enable Cloudflare DNS for TLS challenges in your Caddyfile

```Caddyfile
example.com {
  tls {
    dns cloudflare {$CLOUDFLARE_API_TOKEN}
  }

  respond "OK"
}
```
