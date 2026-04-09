package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// Packet types 0 and 1 are reserved for assets and introspector entries.
const counterPacketType = 2

func TestCounterContractWithPacketIntrospection(t *testing.T) {
	ctx := context.Background()

	alice, grpcClient := setupArkSDK(t)
	t.Cleanup(func() {
		grpcClient.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 20000)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	infos, err := grpcClient.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	counterArkadeScript := counterContractArkadeScript(t)
	counterVtxoScript := createCounterVtxoScript(
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(counterArkadeScript),
	)
	counterTapscript := onlyForfeitScript(t, counterVtxoScript)
	counterDeployPkScript := p2trScriptForVtxoScript(t, counterVtxoScript)

	deployArkadeScript := counterDeployArkadeScript(t, counterDeployPkScript)
	stagingVtxoScript := createCounterVtxoScript(
		aliceAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(deployArkadeScript),
	)
	stagingTapscript := onlyForfeitScript(t, stagingVtxoScript)
	stagingTapKey, _, err := stagingVtxoScript.TapTree()
	require.NoError(t, err)

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

	indexerSvc := setupIndexer(t)
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

	encodeCheckpoints := func(checkpoints []*psbt.Packet) []string {
		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}
		return encodedCheckpoints
	}

	submitAndFinalize := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		encodedCheckpoints := encodeCheckpoints(checkpoints)

		signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(
			ctx, encodedTx, encodedCheckpoints,
		)
		require.NoError(t, err)

		txid, _, signedByServerCheckpoints, err := grpcClient.SubmitTx(
			ctx, signedTx, encodedCheckpoints,
		)
		require.NoError(t, err)
		require.Len(t, signedByIntrospectorCheckpoints, len(signedByServerCheckpoints))

		finalCheckpoints := make([]string, 0, len(signedByServerCheckpoints))
		for i, checkpoint := range signedByServerCheckpoints {
			introspectorCheckpointPtx, err := psbt.NewFromRawBytes(
				strings.NewReader(signedByIntrospectorCheckpoints[i]), true,
			)
			require.NoError(t, err)

			checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
			require.NoError(t, err)

			checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
				checkpointPtx.Inputs[0].TaprootScriptSpendSig,
				introspectorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
			)

			finalCheckpoint, err := checkpointPtx.B64Encode()
			require.NoError(t, err)
			finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
		}

		require.NoError(t, grpcClient.FinalizeTx(ctx, txid, finalCheckpoints))
	}

	submitExpectIntrospectorFailure := func(candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		_, _, err = introspectorClient.SubmitTx(ctx, encodedTx, encodeCheckpoints(checkpoints))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	deployTx, deployCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{stagingInput},
		[]*wire.TxOut{{Value: stagingOutput.Value, PkScript: counterDeployPkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)
	addCounterPacket(t, deployTx, 0)
	addIntrospectorPacket(t, deployTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: deployArkadeScript},
	})
	requireCounterPacket(t, deployTx.UnsignedTx, 0)
	require.NoError(t, executeArkadeScripts(t, deployTx, deployCheckpoints, introspectorPubKey))
	submitAndFinalize(deployTx, deployCheckpoints)

	firstCounterInput := vtxoInputFromScriptOutput(
		t,
		deployTx.UnsignedTx,
		0,
		counterVtxoScript,
		counterTapscript,
	)
	firstCounterPkScript, err := checkpointInputPkScript(firstCounterInput, checkpointScriptBytes)
	require.NoError(t, err)

	invalidUnlockTx, invalidUnlockCheckpoints := buildCounterUnlockTx(
		t,
		firstCounterInput,
		firstCounterPkScript,
		checkpointScriptBytes,
		counterArkadeScript,
		deployTx.UnsignedTx,
		0,
	)
	require.Error(t, executeArkadeScripts(t, invalidUnlockTx, invalidUnlockCheckpoints, introspectorPubKey))
	submitExpectIntrospectorFailure(invalidUnlockTx, invalidUnlockCheckpoints)

	firstUnlockTx, firstUnlockCheckpoints := buildCounterUnlockTx(
		t,
		firstCounterInput,
		firstCounterPkScript,
		checkpointScriptBytes,
		counterArkadeScript,
		deployTx.UnsignedTx,
		1,
	)
	requireCounterPacket(t, firstUnlockTx.UnsignedTx, 1)
	require.Equal(t, firstCounterPkScript, firstUnlockTx.UnsignedTx.TxOut[0].PkScript)
	require.NoError(t, executeArkadeScripts(t, firstUnlockTx, firstUnlockCheckpoints, introspectorPubKey))
	submitAndFinalize(firstUnlockTx, firstUnlockCheckpoints)

	secondCounterInput := checkpointedCounterVtxoInput(
		t,
		firstUnlockTx.UnsignedTx,
		0,
		checkpointScriptBytes,
		counterTapscript,
	)
	secondCounterPkScript, err := checkpointInputPkScript(secondCounterInput, checkpointScriptBytes)
	require.NoError(t, err)
	require.Equal(t, firstCounterPkScript, secondCounterPkScript)

	secondUnlockTx, secondUnlockCheckpoints := buildCounterUnlockTx(
		t,
		secondCounterInput,
		secondCounterPkScript,
		checkpointScriptBytes,
		counterArkadeScript,
		firstUnlockTx.UnsignedTx,
		2,
	)
	requireCounterPacket(t, secondUnlockTx.UnsignedTx, 2)
	require.Equal(t, secondCounterPkScript, secondUnlockTx.UnsignedTx.TxOut[0].PkScript)
	require.NoError(t, executeArkadeScripts(t, secondUnlockTx, secondUnlockCheckpoints, introspectorPubKey))
	submitAndFinalize(secondUnlockTx, secondUnlockCheckpoints)
}

// arkd requires its signer in every forfeit leaf. The dummy counter contract
// adds no owner key: only the server signer and tweaked introspector sign.
func createCounterVtxoScript(
	serverSigner *btcec.PublicKey,
	introspectorPubKey *btcec.PublicKey,
	arkadeScriptHash []byte,
) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					serverSigner,
					arkade.ComputeArkadeScriptPublicKey(introspectorPubKey, arkadeScriptHash),
				},
			},
		},
	}
}

func counterDeployArkadeScript(t *testing.T, counterDeployPkScript []byte) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(counterPacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(counterPacketPayload(0)).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(counterDeployPkScript[2:]).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

func counterContractArkadeScript(t *testing.T) []byte {
	t.Helper()

	arkadeScript, err := txscript.NewScriptBuilder().
		AddInt64(counterPacketType).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(counterPacketPayload(1)).
		AddOp(arkade.OP_ADD64).
		AddOp(arkade.OP_VERIFY).
		AddInt64(counterPacketType).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

func buildCounterUnlockTx(
	t *testing.T,
	input offchain.VtxoInput,
	nextPkScript []byte,
	checkpointScriptBytes []byte,
	arkadeScript []byte,
	prevArkTx *wire.MsgTx,
	counterValue uint64,
) (*psbt.Packet, []*psbt.Packet) {
	t.Helper()

	counterTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{input},
		[]*wire.TxOut{{Value: input.Amount, PkScript: nextPkScript}},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addCounterPacket(t, counterTx, counterValue)
	addIntrospectorPacket(t, counterTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript},
	})
	require.NoError(t, txutils.SetArkPsbtField(counterTx, 0, arkade.PrevoutTxField, *prevArkTx))

	return counterTx, checkpoints
}

func onlyForfeitScript(t *testing.T, vtxoScript script.TapscriptsVtxoScript) []byte {
	t.Helper()

	closures := vtxoScript.ForfeitClosures()
	require.Len(t, closures, 1)

	tapscript, err := closures[0].Script()
	require.NoError(t, err)

	return tapscript
}

func p2trScriptForVtxoScript(t *testing.T, vtxoScript script.TapscriptsVtxoScript) []byte {
	t.Helper()

	tapKey, _, err := vtxoScript.TapTree()
	require.NoError(t, err)

	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	return pkScript
}

func vtxoInputFromScriptOutput(
	t *testing.T,
	prevTx *wire.MsgTx,
	outIndex uint32,
	vtxoScript script.TapscriptsVtxoScript,
	tapscript []byte,
) offchain.VtxoInput {
	t.Helper()

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	expectedPkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	require.Equal(t, expectedPkScript, prevTx.TxOut[outIndex].PkScript)

	merkleProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(tapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	revealedTapscripts, err := vtxoScript.Encode()
	require.NoError(t, err)

	return offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  prevTx.TxHash(),
			Index: outIndex,
		},
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		},
		Amount:             prevTx.TxOut[outIndex].Value,
		RevealedTapscripts: revealedTapscripts,
	}
}

func checkpointedCounterVtxoInput(
	t *testing.T,
	prevTx *wire.MsgTx,
	outIndex uint32,
	checkpointScriptBytes []byte,
	counterTapscript []byte,
) offchain.VtxoInput {
	t.Helper()

	signerUnrollScriptClosure := &script.CSVMultisigClosure{}
	valid, err := signerUnrollScriptClosure.Decode(checkpointScriptBytes)
	require.NoError(t, err)
	require.True(t, valid)

	counterClosure, err := script.DecodeClosure(counterTapscript)
	require.NoError(t, err)

	checkpointVtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{signerUnrollScriptClosure, counterClosure},
	}

	return vtxoInputFromScriptOutput(t, prevTx, outIndex, checkpointVtxoScript, counterTapscript)
}

func findTaprootOutput(t *testing.T, tx *wire.MsgTx, tapKey *btcec.PublicKey) (uint32, *wire.TxOut) {
	t.Helper()

	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	for index, output := range tx.TxOut {
		if bytes.Equal(output.PkScript, pkScript) {
			return uint32(index), output
		}
	}

	require.FailNow(t, "taproot output not found")
	return 0, nil
}

func addCounterPacket(t *testing.T, ptx *psbt.Packet, value uint64) {
	t.Helper()

	addExtensionPacket(t, ptx, extension.UnknownPacket{
		PacketType: counterPacketType,
		Data:       counterPacketPayload(value),
	})
}

func counterPacketPayload(value uint64) []byte {
	return uint64LE(value)
}

func requireCounterPacket(t *testing.T, tx *wire.MsgTx, want uint64) {
	t.Helper()

	ext, err := extension.NewExtensionFromTx(tx)
	require.NoError(t, err)

	for _, packet := range ext {
		if packet.Type() != counterPacketType {
			continue
		}
		data, err := packet.Serialize()
		require.NoError(t, err)
		require.Equal(t, counterPacketPayload(want), data)
		return
	}

	require.FailNow(t, "counter packet not found")
}

func addExtensionPacket(t *testing.T, ptx *psbt.Packet, packet extension.Packet) {
	t.Helper()

	for index, output := range ptx.UnsignedTx.TxOut {
		if !extension.IsExtension(output.PkScript) {
			continue
		}

		ext, err := extension.NewExtensionFromBytes(output.PkScript)
		require.NoError(t, err)

		ext = append(ext, packet)
		txOut, err := ext.TxOut()
		require.NoError(t, err)

		ptx.UnsignedTx.TxOut[index] = txOut
		return
	}

	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	lastIdx := len(ptx.UnsignedTx.TxOut) - 1
	lastOut := ptx.UnsignedTx.TxOut[lastIdx]
	if bytes.Equal(lastOut.PkScript, txutils.ANCHOR_PKSCRIPT) {
		ptx.UnsignedTx.TxOut[lastIdx] = txOut
		ptx.UnsignedTx.AddTxOut(lastOut)
	} else {
		ptx.UnsignedTx.AddTxOut(txOut)
	}
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}
