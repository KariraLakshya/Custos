#!/bin/sh
# Generates the mTLS certificate set inside the pinned openssl container
# (docs/adr/0009-mtls-envoy-openssl.md). Never run on the host directly:
# certs.mjs runs it with the output directory mounted at /out.
#
# Output (all PEM, ECDSA P-256):
#   ca.crt / ca.key                  the Custos dev CA
#   envoy.crt / envoy.key            Envoy's server certificate (localhost)
#   <service>.crt / <service>.key    one client cert per Custos service, SAN
#                                    spiffe://custos.local/service/<service>
#   envoy-upstream.crt / .key        Envoy's client cert towards the services,
#                                    SAN spiffe://custos.local/proxy/envoy
#   <service>-server.crt / .key      TLS listener of revocation and audit
# With --with-negative-fixtures, also (for the proxy tests only):
#   expired.*        valid CA and SAN, validity entirely in the past
#   wrongca.*        right SAN, signed by an unrelated CA
#   selfsigned.*     right SAN, signed by itself
#   wrongsan.*       valid CA, SAN of a service that isn't allowed
set -eu

OUT=/out
SPIFFE=spiffe://custos.local/service
NEGATIVE=${1:-}

apk add --no-cache --quiet openssl >/dev/null
cd "$OUT"

# Valid from an hour ago: a service checks its certificate at boot, often
# seconds after this ran, and Docker's clock can be slightly ahead of the
# host's. Without the margin a fresh certificate can be "not yet valid".
NOT_BEFORE=$(date -u -d "@$(($(date +%s) - 3600))" +%Y%m%d%H%M%SZ)
VALID=$(date -u -d "@$(($(date +%s) + 825 * 86400))" +%Y%m%d%H%M%SZ)
LIFETIME="-not_before $NOT_BEFORE -not_after $VALID"

newkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null; }

# $1 name, $2 CA basename, $3 extension lines, then extra `openssl x509` options.
sign() {
  name=$1 ca=$2 ext=$3
  shift 3
  printf '%b\n' "$ext" >"$name.ext"
  openssl req -new -key "$name.key" -subj "/CN=$name" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA "$ca.crt" -CAkey "$ca.key" -CAcreateserial \
    -extfile "$name.ext" -out "$name.crt" "$@" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

client_ext() { echo "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:$SPIFFE/$1"; }

make_ca() {
  newkey "$1"
  openssl req -x509 -new -key "$1.key" -subj "/CN=$2" -not_before "$NOT_BEFORE" -not_after "$(date -u -d "@$(($(date +%s) + 3650 * 86400))" +%Y%m%d%H%M%SZ)" -out "$1.crt" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
}

make_ca ca "Custos Dev CA"

newkey envoy
sign envoy ca "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1" $LIFETIME

# Envoy's client certificate for its own connections to the services
# behind it (ADR 0009, part B): only a connection proven to be Envoy may
# carry a trusted x-forwarded-client-cert header.
newkey envoy-upstream
sign envoy-upstream ca "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://custos.local/proxy/envoy" $LIFETIME

# Server certificates for the TLS listener of each service behind Envoy.
# Envoy reaches them as host.docker.internal; tests also use localhost.
for service in revocation audit; do
  newkey "$service-server"
  sign "$service-server" ca "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1" $LIFETIME
done

for service in identity vault revocation; do
  newkey "$service"
  sign "$service" ca "$(client_ext "$service")" $LIFETIME
done

if [ "$NEGATIVE" = "--with-negative-fixtures" ]; then
  newkey expired
  sign expired ca "$(client_ext identity)" -not_before 20200101000000Z -not_after 20200102000000Z

  make_ca otherca "Not The Custos CA"
  newkey wrongca
  sign wrongca otherca "$(client_ext identity)" $LIFETIME
  rm -f otherca.key otherca.srl

  newkey selfsigned
  openssl req -x509 -new -key selfsigned.key -subj "/CN=selfsigned" -not_before "$NOT_BEFORE" -not_after "$VALID" -out selfsigned.crt \
    -addext "extendedKeyUsage=clientAuth" -addext "subjectAltName=URI:$SPIFFE/identity"

  newkey wrongsan
  sign wrongsan ca "$(client_ext attacker)" $LIFETIME
fi

rm -f ./*.srl
# Owner-only private keys; certs are public.
chmod 600 ./*.key
chmod 644 ./*.crt
# This runs as root (apk needs it). Hand the files back:
# - OWNER set (Linux): everything to the calling user, who also runs Envoy.
# - otherwise (Docker Desktop): Envoy's image runs as uid 101, so give
#   Envoy its own key, rather than loosening permissions or running Envoy
#   as root.
if [ -n "${OWNER:-}" ]; then
  chown "$OWNER" ./*
else
  chown 101:101 envoy.key envoy-upstream.key
fi
