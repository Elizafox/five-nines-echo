#!/usr/bin/env bash
# Generate a self-signed cert for CN=localhost, valid 365 days.
# Outputs certs/server.crt and certs/server.key alongside this script.
set -euo pipefail
cd "$(dirname "$0")"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 server.key
echo "wrote certs/server.crt and certs/server.key"
