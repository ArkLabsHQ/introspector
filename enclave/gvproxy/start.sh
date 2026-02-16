#!/usr/bin/env sh
# Based on the gvproxy wrapper from the Nitro Enclave reference project.

set -e
set -x

VSOCK_SOCKET="${GVPROXY_SOCKET:-/tmp/network.sock}"
FORWARD_PORTS="${GVPROXY_FORWARD_PORTS:-${ENCLAVE_PORT:-7073}}"

setup_forward() {
  local_port=$1
  remote_port=$2
  curl --unix-socket "${VSOCK_SOCKET}" http:/unix/services/forwarder/expose \
    -X POST \
    -d "{\"local\":\":${local_port}\",\"remote\":\"192.168.127.2:${remote_port}\"}"
}

# Avoid "address already in use" if the socket is left behind.
if [ -S "${VSOCK_SOCKET}" ]; then
  rm -f "${VSOCK_SOCKET}"
fi

# Start gvproxy in the background.
/app/gvproxy -listen vsock://:1024 -listen unix://"${VSOCK_SOCKET}" &
GVPROXY_PID=$!

# Wait for gvproxy to start.
sleep 5

for port in ${FORWARD_PORTS}; do
  setup_forward "${port}" "${port}"
done

wait "${GVPROXY_PID}"
