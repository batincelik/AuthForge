#!/bin/sh
set -eu
mkdir -p "$(dirname "$JWT_PRIVATE_KEY_PATH")"
if [ ! -s "$JWT_PRIVATE_KEY_PATH" ] || [ ! -s "$JWT_PUBLIC_KEY_PATH" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$JWT_PRIVATE_KEY_PATH"
  openssl rsa -pubout -in "$JWT_PRIVATE_KEY_PATH" -out "$JWT_PUBLIC_KEY_PATH"
  chmod 600 "$JWT_PRIVATE_KEY_PATH"
fi
alembic upgrade head
exec uvicorn authforge.main:app --host 0.0.0.0 --port 8000

