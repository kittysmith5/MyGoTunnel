#!/usr/bin/env bash
set -euo pipefail
key=${1:?usage: generate-release-key.sh PRIVATE_KEY.pem [PUBLIC_KEY.pem]}
pub=${2:-${key%.pem}.pub.pem}
umask 077
if [[ -e "$key" || -e "$pub" ]]; then echo 'refusing to overwrite existing signing keys' >&2; exit 1; fi
openssl genpkey -algorithm ED25519 -out "$key"
openssl pkey -in "$key" -pubout -out "$pub"
chmod 600 "$key"
chmod 644 "$pub"
echo "Created Ed25519 keypair; keep the private key offline and never add it to Git."
