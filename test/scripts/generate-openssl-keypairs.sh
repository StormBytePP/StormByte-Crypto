#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# default to script directory/../keys unless overridden by first arg
OUTDIR=${1:-"$SCRIPT_DIR/../keys"}
mkdir -p "$OUTDIR"

echo "Generating keypairs into: $OUTDIR"

# Check openssl
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found in PATH" >&2
  exit 2
fi

# RSA 2048
echo "Generating RSA 2048..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUTDIR/rsa_test.priv.pem"
openssl pkey -in "$OUTDIR/rsa_test.priv.pem" -pubout -out "$OUTDIR/rsa_test.pub.pem"

# DSA 2048
echo "Generating DSA 2048 (may take a bit)..."
DSAPARAM="$OUTDIR/dsaparam.pem"
openssl dsaparam -out "$DSAPARAM" 2048
openssl gendsa -out "$OUTDIR/dsa_test.priv.pem" "$DSAPARAM"
openssl pkey -in "$OUTDIR/dsa_test.priv.pem" -pubout -out "$OUTDIR/dsa_test.pub.pem"
rm -f "$DSAPARAM"

# ECC / ECDSA / ECDH using prime256v1 (secp256r1)
echo "Generating ECC (prime256v1) key for ECC/ECDSA/ECDH..."
openssl ecparam -name prime256v1 -genkey -noout -out "$OUTDIR/ecc_p256_test.priv.pem"
openssl pkey -in "$OUTDIR/ecc_p256_test.priv.pem" -pubout -out "$OUTDIR/ecc_p256_test.pub.pem"
# Duplicate for ECDSA
cp "$OUTDIR/ecc_p256_test.priv.pem" "$OUTDIR/ecdsa_test.priv.pem"
cp "$OUTDIR/ecc_p256_test.pub.pem"  "$OUTDIR/ecdsa_test.pub.pem"
# Duplicate for ECDH
cp "$OUTDIR/ecc_p256_test.priv.pem" "$OUTDIR/ecdh_test.priv.pem"
cp "$OUTDIR/ecc_p256_test.pub.pem"  "$OUTDIR/ecdh_test.pub.pem"

# ED25519
echo "Generating ED25519..."
openssl genpkey -algorithm ED25519 -out "$OUTDIR/ed25519_test.priv.pem"
openssl pkey -in "$OUTDIR/ed25519_test.priv.pem" -pubout -out "$OUTDIR/ed25519_test.pub.pem"

# X25519
echo "Generating X25519..."
openssl genpkey -algorithm X25519 -out "$OUTDIR/x25519_test.priv.pem"
openssl pkey -in "$OUTDIR/x25519_test.priv.pem" -pubout -out "$OUTDIR/x25519_test.pub.pem"

# Print summary
echo "Generated files in $OUTDIR:"
ls -la "$OUTDIR"

echo "Done."