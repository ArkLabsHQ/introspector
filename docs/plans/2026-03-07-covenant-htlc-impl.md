# Covenant HTLC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add unit and integration tests demonstrating a covenant HTLC that allows claiming without the receiver's signature, using Arkade introspection opcodes.

**Architecture:** The covenant HTLC uses two Arkade scripts (claim + refund) that enforce output constraints via `OP_INSPECTOUTPUTSCRIPTPUBKEY` and `OP_INSPECTOUTPUTVALUE`, replacing signature requirements with transaction introspection. These scripts are combined with traditional closure leaves in a tap tree mirroring fulmine's VHTLC structure.

**Tech Stack:** Go, `btcsuite/btcd/txscript`, `arkade-os/arkd/pkg/ark-lib/script`, Arkade script engine

---

### Task 1: Create new branch

**Step 1: Create branch from feat/introspect-introspector-packet**

```bash
cd /c/Git/introspector
git checkout feat/introspect-introspector-packet
git checkout -b feat/covenant-htlc
```

---

### Task 2: Write covenant claim unit tests (engine-level)

**Files:**
- Modify: `pkg/arkade/engine_test.go` (append new test function)

**Step 1: Write the test**

Append `TestCovenantHTLC` to `pkg/arkade/engine_test.go`. This test exercises the Arkade script engine directly — no gRPC, no running services.

The test builds a covenant claim Arkade script that:
1. Pops preimage from witness, verifies `OP_HASH160 <hash> OP_EQUALVERIFY`
2. Pops output index from witness, inspects output scriptPubKey and value
3. Leaves `OP_TRUE` on stack if all checks pass

```go
func TestCovenantHTLC(t *testing.T) {
	t.Parallel()

	// --- Setup: known preimage and its HASH160 ---
	preimage := bytes.Repeat([]byte{0x42}, 32) // 32-byte preimage
	sha := sha256.Sum256(preimage)
	preimageHash := calcHash(sha[:], ripemd160.New()) // RIPEMD160(SHA256(preimage))

	wrongPreimage := bytes.Repeat([]byte{0x43}, 32)

	// --- Setup: receiver taproot output script ---
	receiverWitnessProgram := bytes.Repeat([]byte{0xaa}, 32)
	receiverPkScript := append([]byte{OP_1, OP_DATA_32}, receiverWitnessProgram...)

	wrongWitnessProgram := bytes.Repeat([]byte{0xbb}, 32)
	wrongPkScript := append([]byte{OP_1, OP_DATA_32}, wrongWitnessProgram...)

	// --- Setup: claim amount ---
	const claimAmount int64 = 50000
	claimAmountLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(claimAmountLE, uint64(claimAmount))

	const wrongAmount int64 = 49999
	wrongAmountLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(wrongAmountLE, uint64(wrongAmount))

	// --- Setup: sender taproot output script (for refund) ---
	senderWitnessProgram := bytes.Repeat([]byte{0xcc}, 32)
	senderPkScript := append([]byte{OP_1, OP_DATA_32}, senderWitnessProgram...)

	// --- Build covenant claim script ---
	// Witness stack (bottom to top): <output_index> <preimage>
	// Script: OP_HASH160 <hash> OP_EQUALVERIFY
	//         <idx> OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <wp> OP_EQUALVERIFY
	//         <idx> OP_INSPECTOUTPUTVALUE <amount_le> OP_EQUAL
	covenantClaimScript, err := txscript.NewScriptBuilder().
		AddOp(OP_HASH160).
		AddData(preimageHash).
		AddOp(OP_EQUALVERIFY).
		AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(OP_1).
		AddOp(OP_EQUALVERIFY).
		AddData(receiverWitnessProgram).
		AddOp(OP_EQUALVERIFY).
		AddOp(OP_INSPECTOUTPUTVALUE).
		AddData(claimAmountLE).
		AddOp(OP_EQUAL).
		Script()
	if err != nil {
		t.Fatalf("failed to build covenant claim script: %v", err)
	}

	// --- Build covenant refund script ---
	// Witness stack (bottom to top): <output_index>
	// Script: <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
	//         <idx> OP_INSPECTOUTPUTSCRIPTPUBKEY OP_1 OP_EQUALVERIFY <wp> OP_EQUALVERIFY
	//         <idx> OP_INSPECTOUTPUTVALUE <amount_le> OP_EQUAL
	const refundLocktime int64 = 500000
	covenantRefundScript, err := txscript.NewScriptBuilder().
		AddInt64(refundLocktime).
		AddOp(OP_CHECKLOCKTIMEVERIFY).
		AddOp(OP_DROP).
		AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(OP_1).
		AddOp(OP_EQUALVERIFY).
		AddData(senderWitnessProgram).
		AddOp(OP_EQUALVERIFY).
		AddOp(OP_INSPECTOUTPUTVALUE).
		AddData(claimAmountLE).
		AddOp(OP_EQUAL).
		Script()
	if err != nil {
		t.Fatalf("failed to build covenant refund script: %v", err)
	}

	// --- Shared prevout fetcher ---
	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {Value: 100000, PkScript: []byte{
			OP_1, OP_DATA_32,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},
	})

	// --- Helper: build a tx with given outputs, locktime, and sequence ---
	makeTx := func(outputs []*wire.TxOut, locktime uint32, sequence uint32) *wire.MsgTx {
		return &wire.MsgTx{
			Version:  1,
			LockTime: locktime,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
					Sequence:         sequence,
				},
			},
			TxOut: outputs,
		}
	}

	// --- Helper: run engine ---
	runEngine := func(t *testing.T, script []byte, tx *wire.MsgTx, stack [][]byte) error {
		t.Helper()
		engine, err := NewEngine(
			script, tx, 0,
			txscript.NewSigCache(100),
			txscript.NewTxSigHashes(tx, prevoutFetcher),
			100000, prevoutFetcher,
		)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		if len(stack) > 0 {
			engine.SetStack(stack)
		}
		return engine.Execute()
	}

	// ===== COVENANT CLAIM TESTS =====

	t.Run("covenant_claim_valid", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: claimAmount, PkScript: receiverPkScript},
		}, 0, wire.MaxTxInSequenceNum)
		// Stack (bottom to top): output_index=0, preimage
		stack := [][]byte{{0x00}, preimage}
		err := runEngine(t, covenantClaimScript, tx, stack)
		if err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})

	t.Run("covenant_claim_wrong_preimage", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: claimAmount, PkScript: receiverPkScript},
		}, 0, wire.MaxTxInSequenceNum)
		stack := [][]byte{{0x00}, wrongPreimage}
		err := runEngine(t, covenantClaimScript, tx, stack)
		if err == nil {
			t.Error("expected failure for wrong preimage")
		}
	})

	t.Run("covenant_claim_wrong_address", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: claimAmount, PkScript: wrongPkScript},
		}, 0, wire.MaxTxInSequenceNum)
		stack := [][]byte{{0x00}, preimage}
		err := runEngine(t, covenantClaimScript, tx, stack)
		if err == nil {
			t.Error("expected failure for wrong address")
		}
	})

	t.Run("covenant_claim_wrong_amount", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: wrongAmount, PkScript: receiverPkScript},
		}, 0, wire.MaxTxInSequenceNum)
		stack := [][]byte{{0x00}, preimage}
		err := runEngine(t, covenantClaimScript, tx, stack)
		if err == nil {
			t.Error("expected failure for wrong amount")
		}
	})

	t.Run("covenant_claim_flexible_output_index", func(t *testing.T) {
		t.Parallel()
		// Claim output is at index 1, not 0
		tx := makeTx([]*wire.TxOut{
			{Value: 10000, PkScript: wrongPkScript}, // index 0: some other output
			{Value: claimAmount, PkScript: receiverPkScript}, // index 1: claim output
		}, 0, wire.MaxTxInSequenceNum)
		stack := [][]byte{{0x01}, preimage} // output_index=1
		err := runEngine(t, covenantClaimScript, tx, stack)
		if err != nil {
			t.Errorf("expected success with output at index 1, got: %v", err)
		}
	})

	// ===== COVENANT REFUND TESTS =====

	t.Run("covenant_refund_valid", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: claimAmount, PkScript: senderPkScript},
		}, uint32(refundLocktime), wire.MaxTxInSequenceNum-1) // sequence < max to enable CLTV
		stack := [][]byte{{0x00}} // output_index=0
		err := runEngine(t, covenantRefundScript, tx, stack)
		if err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})

	t.Run("covenant_refund_before_timelock", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: claimAmount, PkScript: senderPkScript},
		}, uint32(refundLocktime-1), wire.MaxTxInSequenceNum-1) // locktime too early
		stack := [][]byte{{0x00}}
		err := runEngine(t, covenantRefundScript, tx, stack)
		if err == nil {
			t.Error("expected failure before timelock")
		}
	})

	t.Run("covenant_refund_wrong_address", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: claimAmount, PkScript: wrongPkScript},
		}, uint32(refundLocktime), wire.MaxTxInSequenceNum-1)
		stack := [][]byte{{0x00}}
		err := runEngine(t, covenantRefundScript, tx, stack)
		if err == nil {
			t.Error("expected failure for wrong refund address")
		}
	})

	t.Run("covenant_refund_wrong_amount", func(t *testing.T) {
		t.Parallel()
		tx := makeTx([]*wire.TxOut{
			{Value: wrongAmount, PkScript: senderPkScript},
		}, uint32(refundLocktime), wire.MaxTxInSequenceNum-1)
		stack := [][]byte{{0x00}}
		err := runEngine(t, covenantRefundScript, tx, stack)
		if err == nil {
			t.Error("expected failure for wrong refund amount")
		}
	})
}
```

**Important notes for the implementer:**
- The `calcHash` function already exists in `pkg/arkade/opcode.go` (used by `opcodeHash160`). It's unexported but accessible from `engine_test.go` since it's in the same package.
- The `sha256` and `ripemd160` imports are already used in the package. Add `"crypto/sha256"`, `"encoding/binary"`, and `"golang.org/x/crypto/ripemd160"` to the test imports.
- The witness stack is set via `engine.SetStack()`. The stack is bottom-to-top, so `[][]byte{{0x00}, preimage}` means output_index is at position 0 (bottom) and preimage is at position 1 (top). The script pops from top first, so it processes preimage first (for `OP_HASH160`), then output_index (for `OP_INSPECTOUTPUTSCRIPTPUBKEY`).

**Step 2: Run tests to verify they pass**

```bash
cd /c/Git/introspector
go test ./pkg/arkade/ -run TestCovenantHTLC -v -count=1
```

Expected: All 8 subtests pass.

**Step 3: Commit**

```bash
git add pkg/arkade/engine_test.go
git commit -m "test: add covenant HTLC unit tests for claim and refund scripts"
```

---

### Task 3: Write integration test for covenant claim

**Files:**
- Create: `test/covenant_htlc_test.go`

**Step 1: Write the integration test**

This test follows the exact pattern from `test/pay_2_out_test.go`. It:
1. Sets up Alice (funder) and Bob (receiver — but Bob does NOT sign the claim)
2. Builds a covenant HTLC Arkade script with hardcoded receiver address + amount
3. Creates a VTXO with the arkade closure (server + introspector multisig, tweaked with arkade script hash)
4. Alice sends funds to the covenant HTLC VTXO
5. Claims using only the preimage — no Bob wallet signing needed
6. Tests invalid case: wrong output → introspector rejects

```go
package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ripemd160"
)

// hash160 computes RIPEMD160(SHA256(data)).
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(sha[:])
	return r.Sum(nil)
}

// TestCovenantHTLCClaim tests the covenant HTLC claim path where the receiver
// does NOT sign — only the preimage is needed. The Arkade script enforces that
// the output goes to the receiver's address with the correct amount.
func TestCovenantHTLCClaim(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	// --- Generate receiver key (Bob) but we will NOT use it for signing the claim ---
	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bobPubKey := bobPrivKey.PubKey()
	bobPkScript, err := txscript.PayToTaprootScript(bobPubKey)
	require.NoError(t, err)
	bobWitnessProgram := bobPkScript[2:] // strip version + push bytes

	// --- Fund Alice ---
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 100_000)

	// --- Preimage setup ---
	preimage := bytes.Repeat([]byte{0x42}, 32)
	preimageHash := hash160(preimage)

	// --- Constants ---
	const sendAmount = 10000
	const claimAmount = 10000

	claimAmountLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(claimAmountLE, uint64(claimAmount))

	// --- Build covenant claim Arkade script ---
	// Witness stack: <output_index> <preimage>
	arkadeScript, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_HASH160).
		AddData(preimageHash).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(bobWitnessProgram).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(claimAmountLE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	// --- Introspector client ---
	introspectorClient, publicKey, connIntrospector := setupIntrospectorClient(t, ctx)
	defer connIntrospector.Close()

	// --- VTXO with Arkade closure ---
	// The multisig closure contains: Bob (receiver), Alice (sender's signer), and
	// the introspector key tweaked with the arkade script hash.
	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, aliceAddr.Signer, publicKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	htlcAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     aliceAddr.Signer,
	}

	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	htlcAddrStr, err := htlcAddr.EncodeV0()
	require.NoError(t, err)

	// --- Alice sends to covenant HTLC ---
	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: htlcAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	// --- Find HTLC output in funding tx ---
	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var htlcOutput *wire.TxOut
	var htlcOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(htlcAddr.VtxoTapKey)) {
			htlcOutput = out
			htlcOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, htlcOutput)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  redeemPtx.UnsignedTx.TxHash(),
			Index: htlcOutputIndex,
		},
		Tapscript:          tapscript,
		Amount:             htlcOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscript)},
	}

	// ========================================
	// CASE 1: Invalid — wrong output address
	// ========================================
	invalidAddrTx, invalidAddrCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: claimAmount, PkScript: []byte{0x6a}}, // OP_RETURN, wrong address
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, invalidAddrTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: append([]byte{0x00}, preimage...)},
	})

	encodedInvalidAddrTx, err := invalidAddrTx.B64Encode()
	require.NoError(t, err)

	encodedInvalidAddrCheckpoints := make([]string, 0, len(invalidAddrCheckpoints))
	for _, cp := range invalidAddrCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedInvalidAddrCheckpoints = append(encodedInvalidAddrCheckpoints, encoded)
	}

	// NOTE: No Bob wallet signing! Only submit to introspector.
	_, _, err = introspectorClient.SubmitTx(ctx, encodedInvalidAddrTx, encodedInvalidAddrCheckpoints)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process transaction")

	// ========================================
	// CASE 2: Valid — covenant claim with correct output
	// ========================================
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: claimAmount, PkScript: bobPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: append([]byte{0x00}, preimage...)},
	})

	encodedValidTx, err := validTx.B64Encode()
	require.NoError(t, err)

	encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedValidCheckpoints = append(encodedValidCheckpoints, encoded)
	}

	// Submit to introspector — no Bob signing needed!
	signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(
		ctx, encodedValidTx, encodedValidCheckpoints,
	)
	require.NoError(t, err)

	// Submit to server
	txid, _, signedByServerCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedByServerCheckpoints))
	for i, checkpoint := range signedByServerCheckpoints {
		byInterceptorCheckpointPtx, err := psbt.NewFromRawBytes(
			strings.NewReader(signedByIntrospectorCheckpoints[i]), true,
		)
		require.NoError(t, err)

		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		require.NoError(t, err)

		checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
			checkpointPtx.Inputs[0].TaprootScriptSpendSig,
			byInterceptorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
		)

		finalCheckpoint, err := checkpointPtx.B64Encode()
		require.NoError(t, err)

		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, txid, finalCheckpoints)
	require.NoError(t, err)
}
```

**Important notes for the implementer:**
- This file uses helpers from `test/utils_test.go`: `setupArkSDK`, `setupIndexer`, `fundAndSettleAlice`, `setupIntrospectorClient`, `createVtxoScriptWithArkadeScript`, `addIntrospectorPacket`
- You'll need to import `"github.com/arkade-os/go-sdk/types"` for `types.Receiver`
- The `Witness` field in `IntrospectorEntry` provides the witness data for the Arkade script. The witness bytes are: `output_index || preimage` (concatenated, not stack-encoded). Check how `VerifyEntry` deserializes witness bytes — it may need the witness to be the raw stack elements or serialized differently. **Read `pkg/arkade/introspector_packet.go:VerifyEntry` to confirm the witness format before finalizing.**
- The integration test requires a running nigiri + arkd + introspector stack
- The `time` import is only needed if you add `time.Sleep` calls between operations

**Step 2: Run test (requires running stack)**

```bash
cd /c/Git/introspector
go test ./test/ -run TestCovenantHTLCClaim -v -count=1 -timeout 120s
```

Expected: Both cases pass — invalid case errors, valid case succeeds.

**Step 3: Commit**

```bash
git add test/covenant_htlc_test.go
git commit -m "test: add integration test for covenant HTLC claim without receiver signature"
```

---

### Task 4: Verify witness format for IntrospectorEntry

**Files:**
- Read: `pkg/arkade/introspector_packet.go` (VerifyEntry function)

**Step 1: Read VerifyEntry to understand how witness bytes are deserialized**

The `Witness` field in `IntrospectorEntry` is passed to the Arkade engine as the initial stack. Check whether it's:
- Raw concatenated bytes (need to split into stack elements)
- Already stack-encoded (serialized witness)
- Passed as-is to `SetStack`

**Step 2: Adjust integration test witness format if needed**

If `VerifyEntry` passes `entry.Witness` as a single byte array to the stack, the witness format in the integration test (`append([]byte{0x00}, preimage...)`) would put everything as one stack element. You may need to encode it differently.

If it uses some form of stack serialization (length-prefixed elements), adjust accordingly.

**Step 3: Re-run tests after any adjustments**

---

### Task 5: Push and create PR

**Step 1: Push branch**

```bash
cd /c/Git/introspector
git push -u origin feat/covenant-htlc
```

**Step 2: Create PR**

```bash
gh pr create \
  --base feat/introspect-introspector-packet \
  --title "test: covenant HTLC claim without receiver signature" \
  --body "$(cat <<'EOF'
## Summary
- Adds unit tests exercising the Arkade script engine with covenant HTLC scripts (claim + refund)
- Adds integration test demonstrating non-interactive HTLC claim using introspection opcodes
- Covenant claim verifies output address + amount via OP_INSPECTOUTPUTSCRIPTPUBKEY and OP_INSPECTOUTPUTVALUE, replacing the receiver's signature
- Inspired by Boltz covenant claims and fulmine's VHTLC structure

## Test plan
- [ ] Unit tests pass: `go test ./pkg/arkade/ -run TestCovenantHTLC -v`
- [ ] Integration tests pass with running stack: `go test ./test/ -run TestCovenantHTLCClaim -v`
EOF
)"
```
