# OP_MERKLEBRANCHVERIFY Design

Replaces the simpler `OP_MERKLEPATHVERIFY` (PR #11) with a more capable
opcode inspired by BIP-116 MERKLEBRANCHVERIFY, adapted for the Arkade
Script VM.

## Motivation

PR #11 introduced `OP_MERKLEPATHVERIFY` (0xf4) — a single-leaf Merkle
path verifier that consumes all stack items and fails on mismatch. This
design improves on it in four ways:

1. **Proof chaining** — pushes the computed root instead of silently
   consuming it, enabling deep-tree verification across multiple calls.
2. **Raw hash mode** — empty `leaf_tag` treats the input as a pre-computed
   32-byte hash, enabling chaining and external hash schemes.
3. **BIP-116 opcode slot** — uses 0xb3 (OP_NOP4), the same slot BIP-116
   proposed for MERKLEBRANCHVERIFY.
4. **Simpler stack** — no count parameter; the caller uses `OP_CAT` to
   compose multi-part leaves before the call.

## References

- [BIP-116: MERKLEBRANCHVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0116.mediawiki)
- [BIP-341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) — lexicographic branch ordering
- [BIP-98: Fast Merkle Trees](https://github.com/bitcoin/bips/blob/master/bip-0098.mediawiki) — position-encoded alternative (not used here)
- Arkade Asset metadata tree (`pkg/ark-lib/asset/utils.go` in arkd) — uses the same lexi-sorted tagged hash convention

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Opcode slot | 0xb3 (OP_NOP4) | Matches BIP-116. Frees 0xf3+ range for introspection opcodes. |
| Sibling ordering | Lexicographic sort | BIP-341 convention used by both Taproot and Arkade metadata. Erases left/right position (membership proofs only, not positional). |
| Output | Push computed root | Enables chaining and 2-of-N same-tree patterns via `OP_EQUALVERIFY`. |
| Pre-hash toggle | Empty leaf_tag = raw 32-byte hash | Eliminates need for a separate mode bit. Natural for chaining (sub-root from prior call is already a hash). |
| Multi-leaf | One leaf per call | Scripts use multiple calls + `OP_EQUALVERIFY` on pushed roots. Avoids BIP-98 structured proof complexity. |
| Count parameter | Dropped | Caller can `OP_CAT` items before the call. No wasted stack element. |
| Depth limit | None artificial | Naturally bounded by 520-byte push limit (~16 levels per call). Chaining extends this at the cost of script bytes. |
| Hash function | BIP-341 tagged hashes (`chainhash.TaggedHash`) | Domain-separated, used throughout Arkade. |

## Specification

### Identity

```
Name:   OP_MERKLEBRANCHVERIFY
Opcode: 0xb3 (179)
```

### Stack (before execution)

```
leaf_data       (top) — raw data, or 32-byte hash if leaf_tag is empty
proof           flat array of 32-byte sibling hashes (may be empty)
branch_tag      non-empty byte string
leaf_tag        byte string (empty = raw hash mode)
```

### Stack (after successful execution)

```
computed_root   32 bytes
```

### Execution

1. Pop `leaf_tag`, `branch_tag`, `proof`, `leaf_data`.
2. Validate:
   - `branch_tag` must be non-empty.
   - `proof` length must be a multiple of 32 (0 is valid — single-leaf tree).
3. Compute leaf hash:
   - If `leaf_tag` is empty: `leaf_data` must be exactly 32 bytes; used as-is.
   - If `leaf_tag` is non-empty: `current = tagged_hash(leaf_tag, leaf_data)`.
4. Walk proof path with lexicographic ordering:
   ```
   for each 32-byte sibling s in proof:
       if current < s:
           current = tagged_hash(branch_tag, current || s)
       else:
           current = tagged_hash(branch_tag, s || current)
   ```
5. Push `current` (32 bytes) onto the stack.

### Error conditions

The script fails if any of:

- Stack has fewer than 4 items.
- `branch_tag` is empty.
- `proof` length is not a multiple of 32.
- `leaf_tag` is empty and `leaf_data` is not exactly 32 bytes.

## Usage Patterns

### Single-leaf verification

```
<leaf_tag> <branch_tag> <proof> <leaf_data>
OP_MERKLEBRANCHVERIFY
<expected_root> OP_EQUALVERIFY
```

### Composite leaf (key + value)

```
<key> <value> OP_CAT
<leaf_tag> <branch_tag> <proof> 3 OP_ROLL
OP_MERKLEBRANCHVERIFY
<expected_root> OP_EQUALVERIFY
```

### Raw hash mode

```
OP_0 <branch_tag> <proof> <32-byte-hash>
OP_MERKLEBRANCHVERIFY
<expected_root> OP_EQUALVERIFY
```

### Proof chaining (deep trees)

```
// Lower path: leaf to intermediate node
<leaf_tag> <branch_tag> <proof_lower> <leaf>
OP_MERKLEBRANCHVERIFY
// sub-root now on stack

// Upper path: sub-root to real root (raw mode)
OP_0 <branch_tag> <proof_upper> 3 OP_ROLL
OP_MERKLEBRANCHVERIFY
<real_root> OP_EQUALVERIFY
```

### Two-leaf same-tree (2-of-N)

```
<leaf_tag> <branch_tag> <proof_A> <leaf_A>
OP_MERKLEBRANCHVERIFY
<leaf_tag> <branch_tag> <proof_B> <leaf_B>
OP_MERKLEBRANCHVERIFY
OP_EQUALVERIFY
```

## Changes Required

### In PR #11 (`feat/op-merklepathverify`)

1. **Rename** `OP_MERKLEPATHVERIFY` (0xf4) to `OP_MERKLEBRANCHVERIFY` (0xb3).
2. **Revert** 0xf4 to `OP_UNKNOWN244`.
3. **Remove** OP_NOP4 from the NOP error handler in `opcodeNop`.
4. **Rewrite** `opcodeMerklePathVerify` -> `opcodeMerkleBranchVerify`:
   - Remove `expected_root` pop and comparison.
   - Add raw hash mode (empty `leaf_tag` check).
   - Push computed root instead of failing on mismatch.
5. **Rewrite tests** in `engine_test.go`:
   - All tests now verify the pushed root via `OP_EQUALVERIFY`.
   - Add raw hash mode tests.
   - Add proof chaining test.
   - Add two-leaf same-tree test.
6. **Update README** opcode table.
7. **Update `opcode_test.go`** disasm expectations.
