#!/bin/sh
# Starts the Nitro Enclave and polls until it exits.
# Designed to run under systemd with Restart=always.
set -eu

NITRO_CLI="${NITRO_CLI_PATH:-/usr/bin/nitro-cli}"
ENCLAVE_NAME="${ENCLAVE_NAME:-app}"
EIF_PATH="${EIF_PATH:-/home/ec2-user/app/server/signing_server.eif}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MIB="${MEMORY_MIB:-4320}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
POLL_INTERVAL="${POLL_INTERVAL_SECONDS:-5}"
DEBUG_FLAG=""

if [ "${DEBUG_MODE:-false}" = "true" ]; then
  DEBUG_FLAG="--debug-mode"
fi

echo "starting enclave '${ENCLAVE_NAME}'"

$NITRO_CLI run-enclave \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB" \
  --eif-path "$EIF_PATH" \
  --enclave-cid "$ENCLAVE_CID" \
  --enclave-name "$ENCLAVE_NAME" \
  $DEBUG_FLAG

# Poll until the enclave stops running.
while $NITRO_CLI describe-enclaves \
  | grep -q "\"EnclaveName\": \"${ENCLAVE_NAME}\""; do
  sleep "$POLL_INTERVAL"
done

echo "enclave '${ENCLAVE_NAME}' is no longer running"
