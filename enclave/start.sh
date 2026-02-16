#!/bin/sh

set -e

# Start viproxy for IMDS access before nitriding sets up full networking
if [ "${ENCLAVE_VIPROXY_ENABLED:-true}" = "true" ]; then
  VIPROXY_IN_ADDRS="${ENCLAVE_VIPROXY_IN_ADDRS:-127.0.0.1:80}"
  VIPROXY_OUT_ADDRS="${ENCLAVE_VIPROXY_OUT_ADDRS:-3:8002}"
  IN_ADDRS="${VIPROXY_IN_ADDRS}" OUT_ADDRS="${VIPROXY_OUT_ADDRS}" /app/proxy &
  if [ -z "${AWS_EC2_METADATA_SERVICE_ENDPOINT:-}" ]; then
    export AWS_EC2_METADATA_SERVICE_ENDPOINT="http://127.0.0.1:80"
  fi
fi

export ENCLAVE_NO_TLS=true

# The AWS SDK needs a region. Inside the enclave, IMDS region detection
# may fail, so we set it explicitly from the deployment config.
if [ -z "${AWS_DEFAULT_REGION:-}" ]; then
  export AWS_DEFAULT_REGION="${ENCLAVE_AWS_REGION:-us-east-1}"
fi
APP_PORT="${ENCLAVE_PROXY_PORT:-7073}"
NITRIDING_EXT_PORT="${ENCLAVE_NITRIDING_EXT_PORT:-443}"
NITRIDING_INT_PORT="${ENCLAVE_NITRIDING_INT_PORT:-8080}"
NITRIDING_PROM_PORT="${ENCLAVE_NITRIDING_PROM_PORT:-9090}"
NITRIDING_PROM_NS="${ENCLAVE_NITRIDING_PROM_NAMESPACE:-enclave}"
NITRIDING_FQDN="${ENCLAVE_NITRIDING_FQDN:-localhost}"

NITRIDING_ARGS="-fqdn ${NITRIDING_FQDN} \
  -ext-pub-port ${NITRIDING_EXT_PORT} \
  -intport ${NITRIDING_INT_PORT} \
  -appwebsrv http://127.0.0.1:${APP_PORT} \
  -prometheus-namespace ${NITRIDING_PROM_NS} \
  -prometheus-port ${NITRIDING_PROM_PORT}"

if [ "${ENCLAVE_NITRIDING_DEBUG:-false}" = "true" ]; then
  NITRIDING_ARGS="${NITRIDING_ARGS} -debug"
fi

# Configure DNS to use gvproxy gateway
echo "nameserver 192.168.127.1" > /etc/resolv.conf

# Start nitriding in background (it will set up networking via gvproxy)
exec /app/nitriding ${NITRIDING_ARGS} -appcmd "/app/enclave-init"
