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
Submits a batch finalization request for signing. Signs forfeits and commitment transactions if the intent proof contains the signer's signature. Validates that forfeits are part of the provided connector tree.

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

## Supported Opcodes

The following opcodes are supported by the Arkade script engine. They extend Bitcoin Script with additional introspection, data manipulation, and cryptographic operations.

### Transaction Introspection (Inputs)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTINPUTOUTPOINT | 199 | 0xc7 | index | txid index | Pushes the transaction ID (32 bytes) and output index (scriptNum) of the input at the given index onto the stack. |
| OP_INSPECTINPUTVALUE | 201 | 0xc9 | index | value | Pushes the value (8 bytes, little-endian) of the previous output spent by the input at the given index. |
| OP_INSPECTINPUTSCRIPTPUBKEY | 202 | 0xca | index | program version | For witness programs: pushes the witness program (2-40 bytes) and segwit version (scriptNum). For non-native segwit: pushes SHA256 hash of scriptPubKey and -1. |
| OP_INSPECTINPUTSEQUENCE | 203 | 0xcb | index | sequence | Pushes the sequence number (4 bytes, little-endian) of the input at the given index. |
| OP_PUSHCURRENTINPUTINDEX | 205 | 0xcd | Nothing | index | Pushes the current input index (scriptNum) being evaluated onto the stack. |

### Transaction Introspection (Outputs)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTOUTPUTVALUE | 207 | 0xcf | index | value | Pushes the value (8 bytes, little-endian) of the output at the given index. |
| OP_INSPECTOUTPUTSCRIPTPUBKEY | 209 | 0xd1 | index | program version | For witness programs: pushes the witness program (2-40 bytes) and segwit version (scriptNum). For non-native segwit: pushes SHA256 hash of scriptPubKey and -1. |

### Transaction Introspection (Transaction)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTVERSION | 210 | 0xd2 | Nothing | version | Pushes the transaction version (4 bytes, little-endian) onto the stack. |
| OP_INSPECTLOCKTIME | 211 | 0xd3 | Nothing | locktime | Pushes the transaction locktime (4 bytes, little-endian) onto the stack. |
| OP_INSPECTNUMINPUTS | 212 | 0xd4 | Nothing | numInputs | Pushes the number of inputs in the transaction (scriptNum) onto the stack. |
| OP_INSPECTNUMOUTPUTS | 213 | 0xd5 | Nothing | numOutputs | Pushes the number of outputs in the transaction (scriptNum) onto the stack. |
| OP_TXWEIGHT | 214 | 0xd6 | Nothing | weight | Pushes the transaction weight (4 bytes, little-endian) onto the stack. Weight is calculated as `SerializeSizeStripped() * 4`. |

### Data Manipulation

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_CAT | 126 | 0x7e | x1 x2 | x1\|x2 | Concatenates two byte arrays. |
| OP_SUBSTR | 127 | 0x7f | x n size | x[n:n+size] | Returns a substring of byte array x starting at position n with length size. |
| OP_LEFT | 128 | 0x80 | x n | x[:n] | Returns the first n bytes of byte array x. |
| OP_RIGHT | 129 | 0x81 | x n | x[len(x)-n:] | Returns the last n bytes of byte array x. |

### Bitwise Logic

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INVERT | 131 | 0x83 | x | ~x | Flips all bits in the input (bitwise NOT). |
| OP_AND | 132 | 0x84 | x1 x2 | x1&x2 | Boolean AND between each bit in the inputs. Operands must be the same length. |
| OP_OR | 133 | 0x85 | x1 x2 | x1\|x2 | Boolean OR between each bit in the inputs. Operands must be the same length. |
| OP_XOR | 134 | 0x86 | x1 x2 | x1^x2 | Boolean exclusive OR between each bit in the inputs. Operands must be the same length. |

### Arithmetic

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_2MUL | 141 | 0x8d | x | x*2 | Multiplies the input by 2. |
| OP_2DIV | 142 | 0x8e | x | x/2 | Divides the input by 2. |
| OP_MUL | 149 | 0x95 | a b | a*b | Multiplies two numbers. |
| OP_DIV | 150 | 0x96 | a b | a/b | Divides a by b. Fails if b is zero. |
| OP_MOD | 151 | 0x97 | a b | a%b | Returns the remainder after dividing a by b. Fails if b is zero. |
| OP_LSHIFT | 152 | 0x98 | x n | x<<n | Logical left shift by n bits. Sign data is discarded. |
| OP_RSHIFT | 153 | 0x99 | x n | x>>n | Logical right shift by n bits. Sign data is discarded. |

### Cryptography

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_CHECKSIGFROMSTACK | 204 | 0xcc | sig pubkey message | True/false | Verifies a Schnorr signature. Pops signature (64 bytes), public key (32 bytes), and message from the stack. Returns 1 if valid, 0 otherwise. If signature is empty, pushes empty vector. |

### 64-bit Arithmetic Operations

These opcodes perform 64-bit arithmetic with overflow checking. All operands must be 8-byte little-endian values.

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_ADD64 | 215 | 0xd7 | a b | sum 1 (or a b 0) | Adds two 64-bit signed integers. On success: pushes sum and 1. On overflow: restores operands and pushes 0. |
| OP_SUB64 | 216 | 0xd8 | a b | diff 1 (or a b 0) | Subtracts b from a (64-bit signed). On success: pushes difference and 1. On overflow: restores operands and pushes 0. |
| OP_MUL64 | 217 | 0xd9 | a b | product 1 (or a b 0) | Multiplies two 64-bit signed integers. On success: pushes product and 1. On overflow: restores operands and pushes 0. |
| OP_DIV64 | 218 | 0xda | a b | remainder quotient 1 (or a b 0) | Divides a by b (64-bit signed). On success: pushes remainder, quotient, and 1. On division by zero or overflow: restores operands and pushes 0. |
| OP_NEG64 | 219 | 0xdb | x | -x 1 (or x 0) | Negates a 64-bit signed integer. On success: pushes result and 1. On overflow: restores operand and pushes 0. |
| OP_LESSTHAN64 | 220 | 0xdc | a b | 1/0 | Returns 1 if a < b (64-bit signed), 0 otherwise. |
| OP_LESSTHANOREQUAL64 | 221 | 0xdd | a b | 1/0 | Returns 1 if a ≤ b (64-bit signed), 0 otherwise. |
| OP_GREATERTHAN64 | 222 | 0xde | a b | 1/0 | Returns 1 if a > b (64-bit signed), 0 otherwise. |
| OP_GREATERTHANOREQUAL64 | 223 | 0xdf | a b | 1/0 | Returns 1 if a ≥ b (64-bit signed), 0 otherwise. |

### Conversion Operations

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_SCRIPTNUMTOLE64 | 224 | 0xe0 | scriptNum | le64 | Converts a scriptNum to an 8-byte little-endian value. |
| OP_LE64TOSCRIPTNUM | 225 | 0xe1 | le64 | scriptNum | Converts an 8-byte little-endian value to a scriptNum. |
| OP_LE32TOLE64 | 226 | 0xe2 | le32 | le64 | Converts a 4-byte little-endian value to an 8-byte little-endian value (sign-extended). |

### Elliptic Curve Operations

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_ECMULSCALARVERIFY | 227 | 0xe3 | k P Q | Nothing/fail | Verifies that Q = k*P where k is a 32-byte scalar, P is a compressed public key, and Q is a compressed public key. Fails if verification fails. |
| OP_TWEAKVERIFY | 228 | 0xe4 | P k Q | Nothing/fail | Verifies that Q = P + k*G where P is a 32-byte X-only internal key, k is a 32-byte big-endian scalar, Q is a 33-byte compressed point, and G is the generator point. Fails if verification fails. |

### SHA256 Streaming Operations

These opcodes allow incremental SHA256 hashing by maintaining hash state on the stack.

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_SHA256INITIALIZE | 196 | 0xc4 | data | state | Initializes a SHA256 context with the given data and pushes the hash state onto the stack. |
| OP_SHA256UPDATE | 197 | 0xc5 | data state | newState | Updates a SHA256 context by adding data to the stream being hashed. Pushes the updated state. |
| OP_SHA256FINALIZE | 198 | 0xc6 | data state | hash | Finalizes a SHA256 hash by adding data and completing padding. Pushes the final 32-byte hash value. |

### Asset Introspection Opcodes

These opcodes provide access to the Arkade Asset V1 packet embedded in the transaction. Asset IDs are represented as two stack items: (txid32, gidx_u16).

#### Packet & Groups

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTNUMASSETGROUPS | 229 | 0xe5 | Nothing | K | Returns the number of asset groups in the packet. |
| OP_INSPECTASSETGROUPASSETID | 230 | 0xe6 | k | txid32 gidx_u16 | Returns the Asset ID of group k. Fresh groups use this transaction's ID. |
| OP_INSPECTASSETGROUPCTRL | 231 | 0xe7 | k | -1 or txid32 gidx_u16 | Returns the control Asset ID if present, else -1. |
| OP_FINDASSETGROUPBYASSETID | 232 | 0xe8 | txid32 gidx_u16 | -1 or k | Finds group index by Asset ID, or -1 if absent. |

#### Metadata

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTASSETGROUPMETADATAHASH | 233 | 0xe9 | k | hash32 | Returns the immutable metadata Merkle root (set at genesis). |

#### Per-Group I/O

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTASSETGROUPNUM | 234 | 0xea | k source_u8 | count_u16 or in_u16 out_u16 | Returns count of inputs/outputs. source: 0=inputs, 1=outputs, 2=both. |
| OP_INSPECTASSETGROUP | 235 | 0xeb | k j source_u8 | type_u8 [data...] amount_u64 | Returns j-th input/output of group k. source: 0=input, 1=output. |
| OP_INSPECTASSETGROUPSUM | 236 | 0xec | k source_u8 | sum_u64 or in_u64 out_u64 | Returns sum of amounts with overflow safety. source: 0=inputs, 1=outputs, 2=both. |

**OP_INSPECTASSETGROUP return values by type:**
- LOCAL input (0x01): `type_u8 input_index_u32 amount_u64`
- INTENT input (0x02): `type_u8 txid_32 output_index_u32 amount_u64`
- LOCAL output (0x01): `type_u8 output_index_u32 amount_u64`

#### Cross-Output (Multi-Asset per UTXO)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTOUTASSETCOUNT | 237 | 0xed | o | n | Returns number of asset entries assigned to output o. |
| OP_INSPECTOUTASSETAT | 238 | 0xee | o t | txid32 gidx_u16 amount_u64 | Returns t-th asset at output o. |
| OP_INSPECTOUTASSETLOOKUP | 239 | 0xef | o txid32 gidx_u16 | amount_u64 or -1 | Returns amount of asset at output o, or -1 if not found. |

#### Cross-Input (Packet-Declared)

| Word | Opcode | Hex | Input | Output | Description |
|------|--------|-----|-------|--------|-------------|
| OP_INSPECTINASSETCOUNT | 240 | 0xf0 | i | n | Returns number of assets declared for input i. |
| OP_INSPECTINASSETAT | 241 | 0xf1 | i t | txid32 gidx_u16 amount_u64 | Returns t-th asset declared for input i. |
| OP_INSPECTINASSETLOOKUP | 242 | 0xf2 | i txid32 gidx_u16 | amount_u64 or -1 | Returns declared amount for asset at input i, or -1 if not found. |

