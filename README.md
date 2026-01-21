# Introspector

## API

### GetInfo
Returns service information including the signer's public key.

**Endpoint**: `GET /v1/info`

**Response**:
```json
{
  "version": "0.0.1",
  "signer_pubkey": "02..."
}
```

### SubmitTx
Submits an Ark transaction for signing along with associated checkpoint transactions.

**Endpoint**: `POST /v1/tx/submit`

**Request**:
```json
{
  "ark_tx": "base64_encoded_psbt",
  "checkpoint_txs": ["base64_encoded_checkpoint_psbt1", "..."]
}
```

**Response**:
```json
{
  "signed_ark_tx": "base64_encoded_signed_psbt",
  "signed_checkpoint_txs": ["base64_encoded_signed_checkpoint_psbt1", "..."]
}
```

## Configuration

The service can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `INTROSPECTOR_SECRET_KEY` | Private key for signing (hex encoded) | Required |
| `INTROSPECTOR_DATADIR` | Data directory path | OS-specific app data dir |
| `INTROSPECTOR_PORT` | gRPC server port | 7073 |
| `INTROSPECTOR_NO_TLS` | Disable TLS encryption | false |
| `INTROSPECTOR_TLS_EXTRA_IPS` | Additional IPs for TLS cert | [] |
| `INTROSPECTOR_TLS_EXTRA_DOMAINS` | Additional domains for TLS cert | [] |
| `INTROSPECTOR_LOG_LEVEL` | Log level (0-6) | 4 (Debug) |

## Development

### Prerequisites

- Go 1.25.3+
- Docker and Docker Compose
- Buf CLI (for protocol buffer generation)

### Building

```bash
# Generate protocol buffer stubs
make proto

# Build the application
make build
```

### Running

```bash
# Run with development configuration
make run
```

### Testing

```bash
# Run docker infrastructure
make docker-run

# Run integration tests
make integrationtest
```
