package test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Packet type 2 for contract state (0=assets, 1=introspector).
const statePacketType = 2

// Fixed state payload carried by the main contract across spends.
var fixedStatePayload = uint64LE(0xdeadbeef)

// TestContractIdWithAssetIdentity exercises the contract identity pattern:
//   - A main contract carries a unique asset (contract ID) and fixed state.
//     It enforces output continuation (same script, asset forwarded, state preserved).
//   - A reader contract is co-spent with the main contract, verifies the main
//     contract's asset identity via OP_INSPECTINASSETLOOKUP, and reads the state
//     from the current transaction's packet.
func TestContractIdWithAssetIdentity(t *testing.T) {
	ctx := context.Background()

	alice, grpcClient := setupArkSDK(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 50000)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	infos, err := grpcClient.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)

	// Recipient for the reader's value after the co-spend.
	recipientKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	recipientPkScript, err := txscript.PayToTaprootScript(recipientKey.PubKey())
	require.NoError(t, err)

	submitAndFinalize := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, encodedTx, encodedCheckpoints)
		require.NoError(t, err)

		opts := indexer.GetVtxosRequestOption{}
		err = opts.WithOutpoints([]types.Outpoint{{Txid: candidateTx.UnsignedTx.TxID(), VOut: 0}})
		require.NoError(t, err)

		vtxos, err := indexerSvc.GetVtxos(ctx, opts)
		require.NoError(t, err)
		require.Len(t, vtxos.Vtxos, 1)
		require.True(t, vtxos.Vtxos[0].Preconfirmed)
		require.False(t, vtxos.Vtxos[0].Spent)
	}

	// =========================================================================
	// Phase 1: Compile the main contract and its deploy script.
	// =========================================================================

	mainArkadeScript := mainContractArkadeScript(t)
	mainVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(mainArkadeScript),
	)
	mainTapscript := onlyForfeitScript(t, mainVtxoScript)
	mainPkScript := p2trScriptForVtxoScript(t, mainVtxoScript)

	deployArkadeScript := contractIdDeployArkadeScript(t, mainPkScript)
	stagingVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(deployArkadeScript),
	)
	stagingTapscript := onlyForfeitScript(t, stagingVtxoScript)
	stagingTapKey, _, err := stagingVtxoScript.TapTree()
	require.NoError(t, err)

	// =========================================================================
	// Phase 2: Fund the staging UTXO and deploy the main contract.
	// =========================================================================

	stagingAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: stagingTapKey,
		Signer:     aliceAddr.Signer,
	}
	stagingAddr, err := stagingAddress.EncodeV0()
	require.NoError(t, err)

	stagingTxid, err := alice.SendOffChain(
		ctx,
		[]types.Receiver{{To: stagingAddr, Amount: 20000}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, stagingTxid)

	stagingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{stagingTxid})
	require.NoError(t, err)
	require.Len(t, stagingTxs.Txs, 1)

	stagingPtx, err := psbt.NewFromRawBytes(strings.NewReader(stagingTxs.Txs[0]), true)
	require.NoError(t, err)

	stagingOutputIndex, stagingOutput := findTaprootOutput(t, stagingPtx.UnsignedTx, stagingTapKey)
	stagingInput := vtxoInputFromScriptOutput(
		t,
		stagingPtx.UnsignedTx,
		stagingOutputIndex,
		stagingVtxoScript,
		stagingTapscript,
	)

	// Build the deploy tx: staging → main contract UTXO.
	deployTx, deployCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{stagingInput},
		[]*wire.TxOut{{Value: stagingOutput.Value, PkScript: mainPkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Genesis asset issuance: 1 unit at output 0.
	issuancePacket := createIssuanceAssetPacket(t, 0, 1)
	addAssetPacketToTx(t, deployTx, issuancePacket)

	// State packet with fixed payload.
	addStatePacket(t, deployTx, fixedStatePayload)

	// Introspector packet for the deploy script.
	addIntrospectorPacket(t, deployTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: deployArkadeScript},
	})

	require.NoError(t, executeArkadeScripts(t, deployTx, introspectorPubKey))
	submitAndFinalize(deployTx, deployCheckpoints)

	// =========================================================================
	// Phase 3: Compile the reader contract (needs the deploy tx hash).
	// =========================================================================

	deployTxHash := deployTx.UnsignedTx.TxHash()

	readerArkadeScript := readerContractArkadeScript(t, deployTxHash)
	readerVtxoScript := createArkadeOnlyVtxoScript(
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(readerArkadeScript),
	)
	readerTapscript := onlyForfeitScript(t, readerVtxoScript)
	readerTapKey, _, err := readerVtxoScript.TapTree()
	require.NoError(t, err)

	// =========================================================================
	// Phase 4: Fund the reader UTXO.
	// =========================================================================

	readerAddress := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: readerTapKey,
		Signer:     aliceAddr.Signer,
	}
	readerAddr, err := readerAddress.EncodeV0()
	require.NoError(t, err)

	readerTxid, err := alice.SendOffChain(
		ctx,
		[]types.Receiver{{To: readerAddr, Amount: 10000}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, readerTxid)

	readerTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{readerTxid})
	require.NoError(t, err)
	require.Len(t, readerTxs.Txs, 1)

	readerPtx, err := psbt.NewFromRawBytes(strings.NewReader(readerTxs.Txs[0]), true)
	require.NoError(t, err)

	readerOutputIndex, _ := findTaprootOutput(t, readerPtx.UnsignedTx, readerTapKey)
	readerInput := vtxoInputFromScriptOutput(
		t,
		readerPtx.UnsignedTx,
		readerOutputIndex,
		readerVtxoScript,
		readerTapscript,
	)

	// =========================================================================
	// Phase 5: Co-spend main + reader.
	// =========================================================================

	// Build the main contract input from the deploy tx output.
	mainInput := vtxoInputFromScriptOutput(
		t,
		deployTx.UnsignedTx,
		0,
		mainVtxoScript,
		mainTapscript,
	)
	mainOutputPkScript, err := checkpointInputPkScript(mainInput, checkpointScriptBytes)
	require.NoError(t, err)

	coSpendTx, coSpendCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{mainInput, readerInput},
		[]*wire.TxOut{
			{Value: mainInput.Amount, PkScript: mainOutputPkScript},
			{Value: readerInput.Amount, PkScript: recipientPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Transfer asset packet: forward the asset from input 0 to output 0.
	transferPacket := createTransferAssetPacket(t, deployTxHash, 0, 0, 0, 1)
	addAssetPacketToTx(t, coSpendTx, transferPacket)

	// State packet with the same fixed payload.
	addStatePacket(t, coSpendTx, fixedStatePayload)

	// Introspector packet for both inputs.
	addIntrospectorPacket(t, coSpendTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: mainArkadeScript},
		{Vin: 1, Script: readerArkadeScript},
	})

	// The main contract needs the deploy tx for OP_INSPECTINPUTPACKET.
	require.NoError(t, txutils.SetArkPsbtField(coSpendTx, 0, arkade.PrevoutTxField, *deployTx.UnsignedTx))

	require.NoError(t, executeArkadeScripts(t, coSpendTx, introspectorPubKey))
	submitAndFinalize(coSpendTx, coSpendCheckpoints)
}

// contractIdDeployArkadeScript builds the deploy script that transitions the
// staging UTXO into the main contract. It verifies:
//   - State packet exists with the fixed payload
//   - Output 0 goes to the main contract pkscript
//   - Exactly 1 asset group with output sum = 1
//   - Value is preserved
func contractIdDeployArkadeScript(t *testing.T, mainPkScript []byte) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		// Verify state packet.
		AddInt64(statePacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(fixedStatePayload).
		AddOp(arkade.OP_EQUALVERIFY).
		// Verify output 0 goes to main contract.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(mainPkScript[2:]). // witness program only
		AddOp(arkade.OP_EQUALVERIFY).
		// Verify exactly 1 asset group.
		AddOp(arkade.OP_INSPECTNUMASSETGROUPS).
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Verify asset output sum at group 0 = 1.
		AddInt64(0). // group index
		AddInt64(1). // source = outputs
		AddOp(arkade.OP_INSPECTASSETGROUPSUM).
		AddData(uint64LE(1)).
		AddOp(arkade.OP_EQUALVERIFY).
		// Verify value preserved (final check leaves result on stack).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

// mainContractArkadeScript builds the recursive main contract script. It verifies:
//   - Discovers own asset ID at runtime via OP_INSPECTASSETGROUPASSETID
//   - Asset is forwarded to output 0 via OP_INSPECTOUTASSETLOOKUP
//   - Previous state matches the fixed payload (OP_INSPECTINPUTPACKET)
//   - Current state matches the fixed payload (OP_INSPECTPACKET)
//   - Output 0 scriptpubkey == input scriptpubkey (continuation)
//   - Value is preserved
func mainContractArkadeScript(t *testing.T) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		// Discover own asset ID and verify it's forwarded to output 0.
		// Stack setup: push output_index first, then OP_INSPECTASSETGROUPASSETID
		// produces [output_index, txid, gidx] ready for OP_INSPECTOUTASSETLOOKUP.
		AddInt64(0). // output index for OP_INSPECTOUTASSETLOOKUP
		AddInt64(0). // group index for OP_INSPECTASSETGROUPASSETID
		AddOp(arkade.OP_INSPECTASSETGROUPASSETID).
		AddOp(arkade.OP_INSPECTOUTASSETLOOKUP).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // found flag == 1
		AddOp(arkade.OP_DROP).        // drop amount

		// Verify previous state matches fixed payload.
		AddInt64(statePacketType).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(fixedStatePayload).
		AddOp(arkade.OP_EQUALVERIFY).

		// Verify current state matches fixed payload.
		AddInt64(statePacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(fixedStatePayload).
		AddOp(arkade.OP_EQUALVERIFY).

		// Verify output continuation: output 0 scriptpubkey == input scriptpubkey.
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).

		// Verify value preserved (final check leaves result on stack).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

// readerContractArkadeScript builds the reader contract script. It verifies:
//   - Input 0 carries the expected asset via OP_INSPECTINASSETLOOKUP
//   - Current transaction's state packet matches the fixed payload
func readerContractArkadeScript(t *testing.T, mainAssetTxid chainhash.Hash) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		// Verify main contract asset at input 0.
		AddInt64(0).               // input index
		AddData(mainAssetTxid[:]). // asset txid (genesis tx hash)
		AddInt64(0).               // group index in current packet
		AddOp(arkade.OP_INSPECTINASSETLOOKUP).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // found flag == 1
		AddOp(arkade.OP_DROP).        // drop amount

		// Read and verify state from current transaction packet.
		AddInt64(statePacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(fixedStatePayload).
		AddOp(arkade.OP_EQUAL). // final check
		Script()
	require.NoError(t, err)

	return arkadeScript
}

func addStatePacket(t *testing.T, ptx *psbt.Packet, payload []byte) {
	t.Helper()

	addExtensionPacket(t, ptx, extension.UnknownPacket{
		PacketType: statePacketType,
		Data:       payload,
	})
}
