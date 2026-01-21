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

**Endpoint**: `POST /v1/tx`

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

### SubmitIntent
Submits an unsigned intent proof for signing. Executes Arkade scripts on the intent proof and signs it. Must be used before registration of the intent.

**Endpoint**: `POST /v1/intent`

**Request**:
```json
{
  "intent": {
    "proof": "base64_encoded_psbt",
    "message": "base64_encoded_register_message"
  }
}
```

**Response**:
```json
{
  "signed_proof": "base64_encoded_signed_psbt"
}
```

### SubmitFinalization
Submits a batch finalization request for signing. Signs forfeits and commitment transactions if the intent proof contains the signer's signature. Validates that forfeits are part of the provided connector and vtxo trees.

**Endpoint**: `POST /v1/finalization`

**Request**:
```json
{
  "signed_intent": {
    "proof": "base64_encoded_signed_psbt",
    "message": "base64_encoded_register_message"
  },
  "forfeits": ["base64_encoded_forfeit_psbt1", "..."],
  "connector_tree": [
    {
      "txid": "transaction_id",
      "tx": "base64_encoded_transaction",
      "children": {
        "0": "child_txid_1",
        "1": "child_txid_2"
      }
    }
  ],
  "vtxo_tree": [
    {
      "txid": "transaction_id",
      "tx": "base64_encoded_transaction",
      "children": {
        "0": "child_txid_1",
        "1": "child_txid_2"
      }
    }
  ],
  "commitment_tx": "base64_encoded_psbt"
}
```

**Response**:
```json
{
  "signed_forfeits": ["base64_encoded_signed_forfeit_psbt1", "..."],
  "signed_commitment_tx": "base64_encoded_signed_psbt"
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

## supported opcodes

OP_INSPECTINPUTOUTPOINT
OP_INSPECTINPUTVALUE
OP_INSPECTINPUTSCRIPTPUBKEY
OP_INSPECTINPUTSEQUENCE
OP_PUSHCURRENTINPUTINDEX
OP_INSPECTOUTPUTVALUE
OP_INSPECTOUTPUTSCRIPTPUBKEY
OP_INSPECTVERSION
OP_INSPECTLOCKTIME
OP_INSPECTNUMINPUTS
OP_INSPECTNUMOUTPUTS
OP_TXWEIGHT
OP_CAT
OP_SUBSTR
OP_LEFT
OP_RIGHT
OP_INVERT
OP_AND
OP_OR
OP_XOR
OP_2MUL
OP_2DIV
OP_MUL
OP_DIV
OP_MOD
OP_LSHIFT
OP_RSHIFT
OP_CHECKSIGFROMSTACK
OP_ADD64
OP_SUB64
OP_MUL64
OP_DIV64
OP_NEG64
OP_LESSTHAN64
OP_LESSTHANOREQUAL64
OP_GREATERTHAN64
OP_GREATERTHANOREQUAL64
OP_SCIPTNUMTOLE64
OP_LE64TOSCIPTNUM
OP_LE32TOLE64
OP_SHA256INITIALIZE
OP_SHA256UPDATE
OP_SHA256FINALIZE
OP_ECMULSCALARVERIFY
OP_TWEAKVERIFY
