package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestCrossInputScriptValidation(t *testing.T) {
	ctx := context.Background()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	_, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcBob.Close()
	})

	aliceAddr := fundAndSettleAlice(t, ctx, alice, 200000)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	recipientPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	recipientPkScript, err := txscript.PayToTaprootScript(recipientPrivKey.PubKey())
	require.NoError(t, err)

	buildScript := func(t *testing.T, ops ...byte) []byte {
		t.Helper()

		builder := txscript.NewScriptBuilder()
		for _, op := range ops {
			builder.AddOp(op)
		}

		script, err := builder.Script()
		require.NoError(t, err)
		return script
	}

	buildInspectInputArkadeScriptHashScript := func(t *testing.T, expectedScriptHash []byte) []byte {
		t.Helper()

		script, err := txscript.NewScriptBuilder().
			AddOp(arkade.OP_1).
			AddOp(arkade.OP_INSPECTINPUTARKADESCRIPTHASH).
			AddData(expectedScriptHash).
			AddOp(arkade.OP_EQUAL).
			Script()
		require.NoError(t, err)
		return script
	}

	buildInspectInputArkadeWitnessHashScript := func(t *testing.T, expectedWitnessHash []byte) []byte {
		t.Helper()

		script, err := txscript.NewScriptBuilder().
			AddOp(arkade.OP_1).
			AddOp(arkade.OP_INSPECTINPUTARKADEWITNESSHASH).
			AddData(expectedWitnessHash).
			AddOp(arkade.OP_EQUAL).
			Script()
		require.NoError(t, err)
		return script
	}

	buildTwoInputSpend := func(t *testing.T, scriptA, scriptB []byte) (*psbt.Packet, []*psbt.Packet) {
		t.Helper()

		const inputAmount int64 = 10000

		vtxoScriptA := createVtxoScriptWithArkadeScript(
			bobPubKey,
			aliceAddr.Signer,
			introspectorPubKey,
			arkade.ArkadeScriptHash(scriptA),
		)

		vtxoScriptB := createVtxoScriptWithArkadeScript(
			bobPubKey,
			aliceAddr.Signer,
			introspectorPubKey,
			arkade.ArkadeScriptHash(scriptB),
		)

		tapKeyA, tapTreeA, err := vtxoScriptA.TapTree()
		require.NoError(t, err)

		tapKeyB, tapTreeB, err := vtxoScriptB.TapTree()
		require.NoError(t, err)

		closureA := vtxoScriptA.ForfeitClosures()[0]
		closureB := vtxoScriptB.ForfeitClosures()[0]

		arkadeTapscriptA, err := closureA.Script()
		require.NoError(t, err)

		arkadeTapscriptB, err := closureB.Script()
		require.NoError(t, err)

		merkleProofA, err := tapTreeA.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(arkadeTapscriptA).TapHash(),
		)
		require.NoError(t, err)

		merkleProofB, err := tapTreeB.GetTaprootMerkleProof(
			txscript.NewBaseTapLeaf(arkadeTapscriptB).TapHash(),
		)
		require.NoError(t, err)

		ctrlBlockA, err := txscript.ParseControlBlock(merkleProofA.ControlBlock)
		require.NoError(t, err)

		ctrlBlockB, err := txscript.ParseControlBlock(merkleProofB.ControlBlock)
		require.NoError(t, err)

		addressA := arklib.Address{
			HRP:        "tark",
			VtxoTapKey: tapKeyA,
			Signer:     aliceAddr.Signer,
		}

		addressB := arklib.Address{
			HRP:        "tark",
			VtxoTapKey: tapKeyB,
			Signer:     aliceAddr.Signer,
		}

		addressAStr, err := addressA.EncodeV0()
		require.NoError(t, err)

		addressBStr, err := addressB.EncodeV0()
		require.NoError(t, err)

		fundingTxid, err := alice.SendOffChain(
			ctx,
			[]types.Receiver{
				{To: addressAStr, Amount: uint64(inputAmount)},
				{To: addressBStr, Amount: uint64(inputAmount)},
			},
		)
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxid)

		fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxs)
		require.Len(t, fundingTxs.Txs, 1)

		fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
		require.NoError(t, err)

		findOutput := func(tapKey *btcec.PublicKey) (*wire.TxOut, uint32) {
			for i, out := range fundingPtx.UnsignedTx.TxOut {
				if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(tapKey)) {
					return out, uint32(i)
				}
			}
			return nil, 0
		}

		outputA, outputIndexA := findOutput(tapKeyA)
		require.NotNil(t, outputA)

		outputB, outputIndexB := findOutput(tapKeyB)
		require.NotNil(t, outputB)

		inputA := offchain.VtxoInput{
			Outpoint: &wire.OutPoint{
				Hash:  fundingPtx.UnsignedTx.TxHash(),
				Index: outputIndexA,
			},
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlockA,
				RevealedScript: merkleProofA.Script,
			},
			Amount:             outputA.Value,
			RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscriptA)},
		}

		inputB := offchain.VtxoInput{
			Outpoint: &wire.OutPoint{
				Hash:  fundingPtx.UnsignedTx.TxHash(),
				Index: outputIndexB,
			},
			Tapscript: &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlockB,
				RevealedScript: merkleProofB.Script,
			},
			Amount:             outputB.Value,
			RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscriptB)},
		}

		candidateTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{inputA, inputB},
			[]*wire.TxOut{{Value: outputA.Value + outputB.Value, PkScript: recipientPkScript}},
			checkpointScriptBytes,
		)
		require.NoError(t, err)
		require.Len(t, candidateTx.UnsignedTx.TxIn, 2)

		return candidateTx, checkpoints
	}

	encodeCheckpoints := func(checkpoints []*psbt.Packet) []string {
		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, checkpoint := range checkpoints {
			encoded, err := checkpoint.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}
		return encodedCheckpoints
	}

	submitAndExpectFailure := func(t *testing.T, candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		t.Helper()

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		encodedCheckpoints := encodeCheckpoints(checkpoints)

		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	executeAndExpectFailure := func(t *testing.T, candidateTx *psbt.Packet, expectedErr string) {
		t.Helper()

		err := executeArkadeScripts(t, candidateTx, introspectorPubKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), expectedErr)
	}

	submitAndFinalize := func(t *testing.T, candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
		t.Helper()

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		encodedCheckpoints := encodeCheckpoints(checkpoints)

		signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.NoError(t, err)

		txid, _, signedByServerCheckpoints, err := grpcBob.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.NoError(t, err)

		finalCheckpoints := make([]string, 0, len(signedByServerCheckpoints))
		for i, checkpoint := range signedByServerCheckpoints {
			finalCheckpoint, err := bobWallet.SignTransaction(ctx, explorer, checkpoint)
			require.NoError(t, err)

			introspectorCheckpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedByIntrospectorCheckpoints[i]), true)
			require.NoError(t, err)

			checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalCheckpoint), true)
			require.NoError(t, err)

			checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
				checkpointPtx.Inputs[0].TaprootScriptSpendSig,
				introspectorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
			)

			finalCheckpoint, err = checkpointPtx.B64Encode()
			require.NoError(t, err)

			finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
		}

		err = grpcBob.FinalizeTx(ctx, txid, finalCheckpoints)
		require.NoError(t, err)
	}

	scriptOne := buildScript(t, arkade.OP_1)
	nonOpOneScript := buildScript(t, arkade.OP_0)
	witnessAwareScript := buildScript(t, arkade.OP_DROP, arkade.OP_1)
	newWitness := func(t *testing.T, items ...[]byte) wire.TxWitness {
		t.Helper()

		witness := wire.TxWitness(items)
		var witBuf bytes.Buffer
		err := psbt.WriteTxWitness(&witBuf, witness)
		require.NoError(t, err)

		decodedWitness, err := txutils.ReadTxWitness(witBuf.Bytes())
		require.NoError(t, err)
		return decodedWitness
	}

	expectedHashOfScriptB := arkade.ArkadeScriptHash(scriptOne)
	scriptHashInspectorScript := buildInspectInputArkadeScriptHashScript(t, expectedHashOfScriptB)

	t.Run("op_inspect_input_arkade_script_hash/invalid_input_does_not_exist", func(t *testing.T) {
		candidateTx, checkpoints := buildTwoInputSpend(t, scriptHashInspectorScript, scriptOne)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: scriptHashInspectorScript},
		})

		executeAndExpectFailure(t, candidateTx, "no introspector entry for vin 1")
		submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_script_hash/invalid_script_hash_mismatch", func(t *testing.T) {
		candidateTx, checkpoints := buildTwoInputSpend(t, scriptHashInspectorScript, nonOpOneScript)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: scriptHashInspectorScript},
			{Vin: 1, Script: nonOpOneScript},
		})

		executeAndExpectFailure(t, candidateTx, "false stack entry at end of script execution")
		submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_script_hash/valid", func(t *testing.T) {
		candidateTx, checkpoints := buildTwoInputSpend(t, scriptHashInspectorScript, scriptOne)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: scriptHashInspectorScript},
			{Vin: 1, Script: scriptOne},
		})

		require.NoError(t, executeArkadeScripts(t, candidateTx, introspectorPubKey))
		submitAndFinalize(t, candidateTx, checkpoints)
	})

	validWitness := newWitness(t, []byte("arkade-witness-valid"))
	var validWitnessBuf bytes.Buffer
	err = psbt.WriteTxWitness(&validWitnessBuf, validWitness)
	require.NoError(t, err)
	expectedWitnessHash := chainhash.TaggedHash(arkade.TagArkWitnessHash, validWitnessBuf.Bytes())
	witnessHashInspectorScript := buildInspectInputArkadeWitnessHashScript(t, expectedWitnessHash[:])

	t.Run("op_inspect_input_arkade_witness_hash/invalid_input_does_not_exist", func(t *testing.T) {
		candidateTx, checkpoints := buildTwoInputSpend(t, witnessHashInspectorScript, witnessAwareScript)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: witnessHashInspectorScript},
		})

		executeAndExpectFailure(t, candidateTx, "no introspector entry for vin 1")
		submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_witness_hash/invalid_witness_hash_mismatch", func(t *testing.T) {
		candidateTx, checkpoints := buildTwoInputSpend(t, witnessHashInspectorScript, witnessAwareScript)
		invalidWitness := newWitness(t, []byte("arkade-witness-invalid"))

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: witnessHashInspectorScript},
			{Vin: 1, Script: witnessAwareScript, Witness: invalidWitness},
		})

		executeAndExpectFailure(t, candidateTx, "false stack entry at end of script execution")
		submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_witness_hash/valid", func(t *testing.T) {
		candidateTx, checkpoints := buildTwoInputSpend(t, witnessHashInspectorScript, witnessAwareScript)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: witnessHashInspectorScript},
			{Vin: 1, Script: witnessAwareScript, Witness: validWitness},
		})

		require.NoError(t, executeArkadeScripts(t, candidateTx, introspectorPubKey))
		submitAndFinalize(t, candidateTx, checkpoints)
	})
}
