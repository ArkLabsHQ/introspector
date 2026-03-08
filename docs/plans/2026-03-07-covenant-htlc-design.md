# Covenant HTLC Design

## Overview

Implement a covenant HTLC variant that allows claiming **without the receiver's signature**, inspired by [Boltz covenant claims](https://api.docs.boltz.exchange/claim-covenants.html) and [fulmine's VHTLC](https://github.com/arklabshq/fulmine). Instead of requiring a signature, the claim path uses Arkade script introspection opcodes to verify the transaction outputs directly — ensuring funds go to the correct address with the correct amount.

## Motivation

Standard HTLCs (like fulmine's VHTLC) require the receiver to be online to sign claim transactions. This creates UX friction for non-interactive scenarios like:
- Lightning reverse swaps where a service claims on behalf of the receiver
- Automated payment flows where the receiver delegates claiming
- Any scenario where the receiver wants to pre-commit a destination and let anyone with the preimage construct the claim

## Architecture

### Tap Tree Structure (6 leaves)

Mirrors fulmine's VHTLC structure, but with covenant variants for the collaborative paths:

| # | Leaf | Closure Type | Signers / Conditions | Purpose |
|---|------|-------------|----------------------|---------|
| 1 | Covenant Claim | Arkade script + `MultisigClosure(server, introspector)` | preimage + output introspection | Non-interactive claim — no receiver sig |
| 2 | Traditional Claim | `ConditionMultisigClosure(receiver, server)` | preimage + receiver_sig + server_sig | Standard interactive claim |
| 3 | Covenant Refund | Arkade script + `MultisigClosure(server, introspector)` | CLTV + output introspection | Non-interactive refund — no sender sig |
| 4 | Traditional Refund | `MultisigClosure(sender, receiver, server)` | sender_sig + receiver_sig + server_sig | Collaborative refund |
| 5 | Refund Without Receiver | `CLTVMultisigClosure(sender, server)` | CLTV + sender_sig + server_sig | Refund when receiver offline |
| 6 | Unilateral Claim | `ConditionCSVMultisigClosure(receiver)` | preimage + receiver_sig + CSV delay | Receiver's exit path |

### Covenant Claim Script (Leaf 1)

The Arkade script enforces output constraints without requiring the receiver's key:

```
# Witness stack (bottom→top): <output_index> <preimage>

OP_HASH160 <preimage_hash> OP_EQUALVERIFY     # verify preimage (pops preimage)
OP_DUP                                         # duplicate output_index for reuse
OP_INSPECTOUTPUTSCRIPTPUBKEY                   # check destination (pops first copy)
OP_1 OP_EQUALVERIFY                            # segwit v1
<receiver_witness_program> OP_EQUALVERIFY      # correct address
OP_INSPECTOUTPUTVALUE                          # check amount (pops second copy)
<expected_amount_le> OP_EQUAL                  # correct amount
```

The receiver's address and amount are hardcoded at script creation time. The witness provides the output index, allowing flexibility in transaction construction (the claim output can be at any position). `OP_DUP` is needed because both `OP_INSPECTOUTPUTSCRIPTPUBKEY` and `OP_INSPECTOUTPUTVALUE` pop the index from the stack.

### Covenant Refund Script (Leaf 3)

Same pattern but gated by a timelock:

```
# Witness stack (bottom→top): <output_index>

<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
OP_DUP
OP_INSPECTOUTPUTSCRIPTPUBKEY
OP_1 OP_EQUALVERIFY
<sender_witness_program> OP_EQUALVERIFY
OP_INSPECTOUTPUTVALUE
<expected_amount_le> OP_EQUAL
```

### How Covenant Paths Work

1. **Script creation**: Receiver's address and claim amount are baked into the Arkade script at VTXO creation time.
2. **Tweaked key**: The introspector's pubkey is tweaked with the Arkade script hash via `ComputeArkadeScriptPublicKey(introspectorPubKey, ArkadeScriptHash(script))`.
3. **Claim**: Anyone with the preimage constructs a transaction with the correct output. The Arkade script verifies the output. The introspector validates and signs (replacing the receiver's signature). The server co-signs.
4. **No receiver interaction needed**: The receiver only needs to provide their address upfront when the HTLC is created.

## Test Plan

### Unit Tests (`pkg/arkade/engine_test.go`)

Exercise the Arkade script engine directly:

- **Covenant claim — valid**: correct preimage + correct output → script succeeds
- **Covenant claim — wrong preimage**: bad preimage → script fails at HASH160 check
- **Covenant claim — wrong output address**: correct preimage but wrong output script → script fails
- **Covenant claim — wrong output amount**: correct preimage but wrong amount → script fails
- **Covenant claim — flexible output index**: preimage valid, output at index 1 instead of 0 → succeeds
- **Covenant refund — valid**: after timelock, correct refund output → succeeds
- **Covenant refund — before timelock**: correct output but locktime not met → fails

### Integration Tests (`test/covenant_htlc_test.go`)

End-to-end with running introspector + arkd stack:

1. Fund a VTXO with the full covenant HTLC tap tree
2. **Covenant claim path**: claim using only the preimage (no receiver wallet signing), verify introspector signs
3. **Invalid covenant claim**: wrong output address → introspector rejects
4. **Covenant refund path** (if time permits): refund after timelock without sender signature

## References

- [Boltz Claim Covenants](https://api.docs.boltz.exchange/claim-covenants.html)
- [BoltzExchange/covclaim](https://github.com/BoltzExchange/covclaim)
- [ArkLabsHQ/fulmine VHTLC](https://github.com/arklabshq/fulmine) — `pkg/vhtlc/`
- Existing test pattern: `test/pay_2_out_test.go`
