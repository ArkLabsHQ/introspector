package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/explorer"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/indexer"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestCrossInputScriptValidation exercises cross-input introspection for
// script hashes, witness hashes, and extension packet payloads.
func TestCrossInputScriptValidation(t *testing.T) {
	env := newCrossInputTestEnv(t)

	// Script-hash inspection cases.
	scriptOne := buildCrossInputScript(t, arkade.OP_1)
	baseScriptTwo := buildCrossInputScript(t, arkade.OP_1, arkade.OP_NOP)
	nonOpOneScript := buildCrossInputScript(t, arkade.OP_0)
	witnessAwareScript := buildCrossInputScript(t, arkade.OP_DROP, arkade.OP_1)

	expectedHashOfScriptB := arkade.ArkadeScriptHash(scriptOne)
	scriptHashInspectorScript := buildInspectInputArkadeScriptHashScript(t, expectedHashOfScriptB)

	t.Run("op_inspect_input_arkade_script_hash/invalid_input_does_not_exist", func(t *testing.T) {
		candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, scriptHashInspectorScript, scriptOne)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: scriptHashInspectorScript},
		})

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "no introspector entry for vin 1")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_script_hash/invalid_script_hash_mismatch", func(t *testing.T) {
		candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, scriptHashInspectorScript, nonOpOneScript)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: scriptHashInspectorScript},
			{Vin: 1, Script: nonOpOneScript},
		})

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "false stack entry at end of script execution")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_script_hash/valid", func(t *testing.T) {
		candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, scriptHashInspectorScript, scriptOne)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: scriptHashInspectorScript},
			{Vin: 1, Script: scriptOne},
		})

		require.NoError(t, executeArkadeScripts(t, candidateTx, env.introspectorPubKey))
		env.submitAndFinalize(t, candidateTx, checkpoints)
	})

	// Witness-hash inspection cases.
	validWitness := newCrossInputWitness(t, []byte("arkade-witness-valid"))
	var validWitnessBuf bytes.Buffer
	err := psbt.WriteTxWitness(&validWitnessBuf, validWitness)
	require.NoError(t, err)
	expectedWitnessHash := chainhash.TaggedHash(arkade.TagArkWitnessHash, validWitnessBuf.Bytes())
	witnessHashInspectorScript := buildInspectInputArkadeWitnessHashScript(t, expectedWitnessHash[:])

	t.Run("op_inspect_input_arkade_witness_hash/invalid_input_does_not_exist", func(t *testing.T) {
		candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, witnessHashInspectorScript, witnessAwareScript)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: witnessHashInspectorScript},
		})

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "no introspector entry for vin 1")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_witness_hash/invalid_witness_hash_mismatch", func(t *testing.T) {
		candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, witnessHashInspectorScript, witnessAwareScript)
		invalidWitness := newCrossInputWitness(t, []byte("arkade-witness-invalid"))

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: witnessHashInspectorScript},
			{Vin: 1, Script: witnessAwareScript, Witness: invalidWitness},
		})

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "false stack entry at end of script execution")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_arkade_witness_hash/valid", func(t *testing.T) {
		candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, witnessHashInspectorScript, witnessAwareScript)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: witnessHashInspectorScript},
			{Vin: 1, Script: witnessAwareScript, Witness: validWitness},
		})

		require.NoError(t, executeArkadeScripts(t, candidateTx, env.introspectorPubKey))
		env.submitAndFinalize(t, candidateTx, checkpoints)
	})

	// Packet inspection cases.
	const inspectPacketType = 3
	inspectPacketPayload := []byte{0xca, 0xfe, 0xba, 0xbe}
	inspectPacketScript := buildInspectPacketScript(t, inspectPacketType, inspectPacketPayload)

	t.Run("op_inspect_packet/valid_found", func(t *testing.T) {
		candidateTx, checkpoints := env.buildInspectPacketSpend(
			t,
			scriptOne,
			inspectPacketScript,
			extension.UnknownPacket{PacketType: inspectPacketType, Data: inspectPacketPayload},
		)

		require.NoError(t, executeArkadeScripts(t, candidateTx, env.introspectorPubKey))
		env.submitAndFinalize(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_packet/valid_not_found", func(t *testing.T) {
		script := buildInspectPacketProbeScript(t, 9, false, nil)
		candidateTx, checkpoints := env.buildInspectPacketSpend(
			t,
			scriptOne,
			script,
			extension.UnknownPacket{PacketType: inspectPacketType, Data: inspectPacketPayload},
		)

		require.NoError(t, executeArkadeScripts(t, candidateTx, env.introspectorPubKey))
		env.submitAndFinalize(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_packet/invalid_packet_type_not_found", func(t *testing.T) {
		script := buildInspectPacketProbeScript(t, 9, true, nil)
		candidateTx, checkpoints := env.buildInspectPacketSpend(
			t,
			scriptOne,
			script,
			extension.UnknownPacket{PacketType: inspectPacketType, Data: inspectPacketPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "OP_EQUALVERIFY failed")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_packet/invalid_payload_mismatch", func(t *testing.T) {
		script := buildInspectPacketScript(t, inspectPacketType, []byte{0xba, 0xad, 0xf0, 0x0d})
		candidateTx, checkpoints := env.buildInspectPacketSpend(
			t,
			scriptOne,
			script,
			extension.UnknownPacket{PacketType: inspectPacketType, Data: inspectPacketPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "false stack entry at end of script execution")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_packet/invalid_packet_type_out_of_range", func(t *testing.T) {
		script := buildInspectPacketProbeScript(t, 256, true, nil)
		candidateTx, checkpoints := env.buildInspectPacketSpend(
			t,
			scriptOne,
			script,
			extension.UnknownPacket{PacketType: inspectPacketType, Data: inspectPacketPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "packet type out of range")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	const packetType = 2
	expectedPayload := []byte{0xde, 0xad, 0xbe, 0xef}
	packetInspectorScript := buildInspectInputPacketScript(t, packetType, 0, expectedPayload)

	t.Run("op_inspect_input_packet/valid", func(t *testing.T) {
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			packetInspectorScript,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		require.NoError(t, executeArkadeScripts(t, candidateTx, env.introspectorPubKey))
		env.submitAndFinalize(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_packet/invalid_packet_type_not_found", func(t *testing.T) {
		script := buildInspectInputPacketProbeScript(t, 9, 0, true, nil)
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			script,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "OP_EQUALVERIFY failed")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_packet/invalid_payload_mismatch", func(t *testing.T) {
		script := buildInspectInputPacketScript(t, packetType, 0, []byte{0xba, 0xad, 0xf0, 0x0d})
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			script,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "false stack entry at end of script execution")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_packet/invalid_input_index_negative", func(t *testing.T) {
		script := buildInspectInputPacketProbeScript(t, packetType, -1, true, nil)
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			script,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "input index cannot be negative")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_packet/invalid_input_index_out_of_range", func(t *testing.T) {
		script := buildInspectInputPacketProbeScript(t, packetType, 2, true, nil)
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			script,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "input index out of range")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_packet/invalid_packet_type_out_of_range", func(t *testing.T) {
		script := buildInspectInputPacketProbeScript(t, 256, 0, true, nil)
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			script,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "packet type out of range")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})

	t.Run("op_inspect_input_packet/invalid_prevout_tx_not_available", func(t *testing.T) {
		candidateTx, checkpoints := env.buildInspectInputPacketSpend(
			t,
			scriptOne,
			baseScriptTwo,
			packetInspectorScript,
			scriptOne,
			extension.UnknownPacket{PacketType: packetType, Data: expectedPayload},
		)

		removePrevoutTxFields(t, candidateTx, 0, 1)

		executeAndExpectFailure(t, candidateTx, env.introspectorPubKey, "prevout tx not available for input 0")
		env.submitAndExpectFailure(t, candidateTx, checkpoints)
	})
}

// crossInputTestEnv bundles the services and common fixtures used by the test.
type crossInputTestEnv struct {
	ctx                   context.Context
	alice                 arksdk.ArkClient
	bobWallet             wallet.WalletService
	bobPubKey             *btcec.PublicKey
	grpcBob               client.TransportClient
	aliceAddr             *arklib.Address
	introspectorClient    introspectorclient.TransportClient
	introspectorPubKey    *btcec.PublicKey
	checkpointScriptBytes []byte
	indexerSvc            indexer.Indexer
	explorer              explorer.Explorer
	recipientPkScript     []byte
}

// spendTemplate captures the spend data needed to locate and spend a VTXO output.
type spendTemplate struct {
	tapKey            *btcec.PublicKey
	pkScript          []byte
	tapscript         *waddrmgr.Tapscript
	revealedTapscript string
}

// newCrossInputTestEnv builds the clients, wallet state, and common scripts for
// cross-input validation scenarios.
func newCrossInputTestEnv(t *testing.T) *crossInputTestEnv {
	t.Helper()

	// Step 1: Create the ark clients and wallet handles used by the test.
	ctx := context.Background()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcAlice.Close()
	})

	_, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() {
		grpcBob.Close()
	})

	// Step 2: Fund Alice and connect to the introspector service.
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 400000)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	// Step 3: Load shared chain data and build the recipient output script.
	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)

	explorerSvc, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	recipientPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	recipientPkScript, err := txscript.PayToTaprootScript(recipientPrivKey.PubKey())
	require.NoError(t, err)

	return &crossInputTestEnv{
		ctx:                   ctx,
		alice:                 alice,
		bobWallet:             bobWallet,
		bobPubKey:             bobPubKey,
		grpcBob:               grpcBob,
		aliceAddr:             aliceAddr,
		introspectorClient:    introspectorClient,
		introspectorPubKey:    introspectorPubKey,
		checkpointScriptBytes: checkpointScriptBytes,
		indexerSvc:            indexerSvc,
		explorer:              explorerSvc,
		recipientPkScript:     recipientPkScript,
	}
}

// buildCrossInputScript assembles a bare script from the provided opcodes.
func buildCrossInputScript(t *testing.T, ops ...byte) []byte {
	t.Helper()

	builder := txscript.NewScriptBuilder()
	for _, op := range ops {
		builder.AddOp(op)
	}

	script, err := builder.Script()
	require.NoError(t, err)
	return script
}

// buildInspectInputArkadeScriptHashScript checks another input's arkade script hash.
func buildInspectInputArkadeScriptHashScript(t *testing.T, expectedScriptHash []byte) []byte {
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

// buildInspectInputArkadeWitnessHashScript checks another input's witness hash.
func buildInspectInputArkadeWitnessHashScript(t *testing.T, expectedWitnessHash []byte) []byte {
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

// buildInspectInputPacketScript checks a packet payload from a previous input tx.
func buildInspectInputPacketScript(t *testing.T, packetType uint8, inputIndex uint32, expectedPayload []byte) []byte {
	t.Helper()

	script, err := txscript.NewScriptBuilder().
		AddInt64(int64(packetType)).
		AddInt64(int64(inputIndex)).
		AddOp(arkade.OP_INSPECTINPUTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(expectedPayload).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	return script
}

// buildInspectPacketScript checks a packet payload from the current transaction.
func buildInspectPacketScript(t *testing.T, packetType uint8, expectedPayload []byte) []byte {
	t.Helper()

	script, err := txscript.NewScriptBuilder().
		AddInt64(int64(packetType)).
		AddOp(arkade.OP_INSPECTPACKET).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(expectedPayload).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	return script
}

// buildInspectPacketProbeScript builds a packet inspection script that can
// express not-found and out-of-range packet type probes.
func buildInspectPacketProbeScript(
	t *testing.T,
	packetType int64,
	expectFound bool,
	expectedPayload []byte,
) []byte {
	t.Helper()

	builder := txscript.NewScriptBuilder().
		AddInt64(packetType).
		AddOp(arkade.OP_INSPECTPACKET)

	if expectFound {
		builder.AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY)
		if expectedPayload != nil {
			builder.AddData(expectedPayload).AddOp(arkade.OP_EQUAL)
		}
	} else {
		builder.AddOp(arkade.OP_0).AddOp(arkade.OP_EQUALVERIFY).AddOp(arkade.OP_0).AddOp(arkade.OP_EQUAL)
	}

	script, err := builder.Script()
	require.NoError(t, err)
	return script
}

// buildInspectInputPacketProbeScript builds a packet inspection script that can
// express out-of-range or negative test operands.
func buildInspectInputPacketProbeScript(
	t *testing.T,
	packetType int64,
	inputIndex int64,
	expectFound bool,
	expectedPayload []byte,
) []byte {
	t.Helper()

	builder := txscript.NewScriptBuilder().
		AddInt64(packetType).
		AddInt64(inputIndex).
		AddOp(arkade.OP_INSPECTINPUTPACKET)

	if expectFound {
		builder.AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY)
		if expectedPayload != nil {
			builder.AddData(expectedPayload).AddOp(arkade.OP_EQUAL)
		}
	} else {
		builder.AddOp(arkade.OP_0).AddOp(arkade.OP_EQUALVERIFY).AddOp(arkade.OP_0).AddOp(arkade.OP_EQUAL)
	}

	script, err := builder.Script()
	require.NoError(t, err)
	return script
}

// buildInspectPacketSpend creates a candidate tx whose current transaction
// extension can be inspected with OP_INSPECTPACKET.
func (env *crossInputTestEnv) buildInspectPacketSpend(
	t *testing.T,
	siblingScript []byte,
	script []byte,
	packets ...extension.Packet,
) (*psbt.Packet, []*psbt.Packet) {
	t.Helper()

	// Step 1: Build a two-input candidate tx using the requested script pair.
	candidateTx, checkpoints, _ := env.buildTwoInputSpend(t, script, siblingScript)

	// Step 2: Attach the packets to the candidate transaction extension output.
	for _, packet := range packets {
		addCrossInputExtensionPacket(t, candidateTx, packet)
	}

	// Step 3: Add introspector entries for the inspected input and its sibling.
	addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: script},
		{Vin: 1, Script: siblingScript},
	})

	return candidateTx, checkpoints
}

// buildInspectInputPacketSpend creates a candidate tx whose previous finalized
// ark transaction can be inspected with OP_INSPECTINPUTPACKET.
func (env *crossInputTestEnv) buildInspectInputPacketSpend(
	t *testing.T,
	baseScriptA []byte,
	baseScriptB []byte,
	scriptA []byte,
	scriptB []byte,
	packet extension.Packet,
) (*psbt.Packet, []*psbt.Packet) {
	t.Helper()

	// Step 1: Build and finalize the previous ark tx carrying the packet.
	candidateTx, checkpoints, _ := env.buildFinalizedPacketChain(
		t,
		baseScriptA,
		baseScriptB,
		scriptA,
		scriptB,
		packet,
		env.submitAndFinalize,
	)

	// Step 2: Add introspector entries for the inspected input and its sibling.
	addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: scriptA},
		{Vin: 1, Script: scriptB},
	})

	return candidateTx, checkpoints
}

// newCrossInputWitness serializes and re-reads witness data in canonical format.
func newCrossInputWitness(t *testing.T, items ...[]byte) wire.TxWitness {
	t.Helper()

	witness := wire.TxWitness(items)
	var witBuf bytes.Buffer
	err := psbt.WriteTxWitness(&witBuf, witness)
	require.NoError(t, err)

	decodedWitness, err := txutils.ReadTxWitness(witBuf.Bytes())
	require.NoError(t, err)
	return decodedWitness
}

// buildSpendTemplate derives the tapscript data needed to fund and later spend a VTXO.
func (env *crossInputTestEnv) buildSpendTemplate(t *testing.T, scriptBytes []byte) spendTemplate {
	t.Helper()

	// Step 1: Build the VTXO script committed to the arkade script hash.
	vtxoScript := createVtxoScriptWithArkadeScript(
		env.bobPubKey,
		env.aliceAddr.Signer,
		env.introspectorPubKey,
		arkade.ArkadeScriptHash(scriptBytes),
	)

	tapKey, tapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]
	arkadeTapscript, err := closure.Script()
	require.NoError(t, err)

	// Step 2: Derive the taproot proof and control block for the spend path.
	merkleProof, err := tapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(arkadeTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	pkScript, err := txscript.PayToTaprootScript(tapKey)
	require.NoError(t, err)

	// Step 3: Return the spend metadata used by the scenario builders.
	return spendTemplate{
		tapKey:   tapKey,
		pkScript: pkScript,
		tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		},
		revealedTapscript: hex.EncodeToString(arkadeTapscript),
	}
}

// addCrossInputExtensionPacket appends a packet to the transaction's extension output.
func addCrossInputExtensionPacket(t *testing.T, ptx *psbt.Packet, packet extension.Packet) {
	t.Helper()

	// Step 1: Reuse the existing extension output when one is already present.
	for i, out := range ptx.UnsignedTx.TxOut {
		if !extension.IsExtension(out.PkScript) {
			continue
		}

		ext, err := extension.NewExtensionFromBytes(out.PkScript)
		require.NoError(t, err)
		ext = append(ext, packet)
		combined, err := ext.Serialize()
		require.NoError(t, err)
		ptx.UnsignedTx.TxOut[i].PkScript = combined
		return
	}

	// Step 2: Otherwise insert a fresh extension output before the trailing output.
	ext := extension.Extension{packet}
	txOut, err := ext.TxOut()
	require.NoError(t, err)

	lastIdx := len(ptx.UnsignedTx.TxOut) - 1
	lastOut := ptx.UnsignedTx.TxOut[lastIdx]
	ptx.UnsignedTx.TxOut[lastIdx] = txOut
	ptx.UnsignedTx.AddTxOut(lastOut)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
}

// findOutputForTemplate locates the output whose script matches the template.
func findOutputForTemplate(t *testing.T, ptx *psbt.Packet, template spendTemplate) (*wire.TxOut, uint32) {
	t.Helper()

	for i, out := range ptx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, template.pkScript) {
			return out, uint32(i)
		}
	}

	return nil, 0
}

// buildVtxoInput converts a funded output and template into an offchain spend input.
func buildVtxoInput(prevTx *psbt.Packet, out *wire.TxOut, outIndex uint32, template spendTemplate) offchain.VtxoInput {
	return offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  prevTx.UnsignedTx.TxHash(),
			Index: outIndex,
		},
		Tapscript:          template.tapscript,
		Amount:             out.Value,
		RevealedTapscripts: []string{template.revealedTapscript},
	}
}

// removePrevoutTxFields removes prevout tx metadata from the selected inputs.
func removePrevoutTxFields(t *testing.T, ptx *psbt.Packet, inputIndexes ...int) {
	t.Helper()

	prevoutFieldKey := append([]byte{txutils.ArkPsbtFieldKeyType}, arkade.ArkFieldPrevoutTx...)

	for _, inputIndex := range inputIndexes {
		require.GreaterOrEqual(t, inputIndex, 0)
		require.Less(t, inputIndex, len(ptx.Inputs))

		unknowns := ptx.Inputs[inputIndex].Unknowns
		filtered := make([]*psbt.Unknown, 0, len(unknowns))
		for _, unknown := range unknowns {
			if bytes.Equal(unknown.Key, prevoutFieldKey) {
				continue
			}
			filtered = append(filtered, unknown)
		}
		ptx.Inputs[inputIndex].Unknowns = filtered
	}
}

// buildFinalizedPacketChain creates a previous finalized ark tx with a packet and
// then returns a candidate tx that spends from it.
func (env *crossInputTestEnv) buildFinalizedPacketChain(
	t *testing.T,
	baseScriptA, baseScriptB, scriptA, scriptB []byte,
	packet extension.Packet,
	finalize func(*testing.T, *psbt.Packet, []*psbt.Packet),
) (*psbt.Packet, []*psbt.Packet, *psbt.Packet) {
	t.Helper()

	// Step 1: Fund two base VTXOs that will feed the packet-carrying transaction.
	const inputAmount int64 = 10000

	baseTemplateA := env.buildSpendTemplate(t, baseScriptA)
	baseTemplateB := env.buildSpendTemplate(t, baseScriptB)

	addressA := arklib.Address{HRP: "tark", VtxoTapKey: baseTemplateA.tapKey, Signer: env.aliceAddr.Signer}
	addressB := arklib.Address{HRP: "tark", VtxoTapKey: baseTemplateB.tapKey, Signer: env.aliceAddr.Signer}
	addressAStr, err := addressA.EncodeV0()
	require.NoError(t, err)
	addressBStr, err := addressB.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := env.alice.SendOffChain(
		env.ctx,
		[]types.Receiver{{To: addressAStr, Amount: uint64(inputAmount)}, {To: addressBStr, Amount: uint64(inputAmount)}},
	)
	require.NoError(t, err)

	fundingTxs, err := env.indexerSvc.GetVirtualTxs(env.ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	fundingOutputA, fundingIndexA := findOutputForTemplate(t, fundingPtx, baseTemplateA)
	require.NotNil(t, fundingOutputA)
	fundingOutputB, fundingIndexB := findOutputForTemplate(t, fundingPtx, baseTemplateB)
	require.NotNil(t, fundingOutputB)

	// Step 2: Build and finalize the previous ark tx that carries the packet.
	previousTemplateA := env.buildSpendTemplate(t, scriptA)
	previousTemplateB := env.buildSpendTemplate(t, scriptB)

	previousArkTx, previousCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			buildVtxoInput(fundingPtx, fundingOutputA, fundingIndexA, baseTemplateA),
			buildVtxoInput(fundingPtx, fundingOutputB, fundingIndexB, baseTemplateB),
		},
		[]*wire.TxOut{{Value: fundingOutputA.Value, PkScript: previousTemplateA.pkScript}, {Value: fundingOutputB.Value, PkScript: previousTemplateB.pkScript}},
		env.checkpointScriptBytes,
	)
	require.NoError(t, err)

	addCrossInputExtensionPacket(t, previousArkTx, packet)
	addIntrospectorPacket(t, previousArkTx, []arkade.IntrospectorEntry{{Vin: 0, Script: baseScriptA}, {Vin: 1, Script: baseScriptB}})

	require.NoError(t, executeArkadeScripts(t, previousArkTx, env.introspectorPubKey))
	finalize(t, previousArkTx, previousCheckpoints)

	prevOutputA, prevIndexA := findOutputForTemplate(t, previousArkTx, previousTemplateA)
	require.NotNil(t, prevOutputA)
	prevOutputB, prevIndexB := findOutputForTemplate(t, previousArkTx, previousTemplateB)
	require.NotNil(t, prevOutputB)

	// Step 3: Build the candidate tx that spends outputs from the finalized tx.
	candidateTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			buildVtxoInput(previousArkTx, prevOutputA, prevIndexA, previousTemplateA),
			buildVtxoInput(previousArkTx, prevOutputB, prevIndexB, previousTemplateB),
		},
		[]*wire.TxOut{{Value: prevOutputA.Value + prevOutputB.Value, PkScript: env.recipientPkScript}},
		env.checkpointScriptBytes,
	)
	require.NoError(t, err)

	// Step 4: Attach prevout tx fields so cross-input opcodes can inspect them.
	require.NoError(t, txutils.SetArkPsbtField(candidateTx, 0, arkade.PrevoutTxField, *previousArkTx.UnsignedTx))
	require.NoError(t, txutils.SetArkPsbtField(candidateTx, 1, arkade.PrevoutTxField, *previousArkTx.UnsignedTx))

	return candidateTx, checkpoints, previousArkTx
}

// buildTwoInputSpend funds two VTXOs directly and returns a candidate two-input spend.
func (env *crossInputTestEnv) buildTwoInputSpend(
	t *testing.T,
	scriptA, scriptB []byte,
	prevArkPackets ...extension.Packet,
) (*psbt.Packet, []*psbt.Packet, *psbt.Packet) {
	t.Helper()

	// Step 1: Derive the spend templates for both scripted inputs.
	const inputAmount int64 = 10000

	templateA := env.buildSpendTemplate(t, scriptA)
	templateB := env.buildSpendTemplate(t, scriptB)

	addressA := arklib.Address{HRP: "tark", VtxoTapKey: templateA.tapKey, Signer: env.aliceAddr.Signer}
	addressB := arklib.Address{HRP: "tark", VtxoTapKey: templateB.tapKey, Signer: env.aliceAddr.Signer}
	addressAStr, err := addressA.EncodeV0()
	require.NoError(t, err)
	addressBStr, err := addressB.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := env.alice.SendOffChain(
		env.ctx,
		[]types.Receiver{{To: addressAStr, Amount: uint64(inputAmount)}, {To: addressBStr, Amount: uint64(inputAmount)}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	fundingTxs, err := env.indexerSvc.GetVirtualTxs(env.ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxs)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	// Step 2: Attach any previous ark packets that the scenario needs.
	for _, packet := range prevArkPackets {
		addCrossInputExtensionPacket(t, fundingPtx, packet)
	}

	// Step 3: Locate the funded outputs that correspond to the requested scripts.
	outputA, outputIndexA := findOutputForTemplate(t, fundingPtx, templateA)
	require.NotNil(t, outputA)
	outputB, outputIndexB := findOutputForTemplate(t, fundingPtx, templateB)
	require.NotNil(t, outputB)

	// Step 4: Build the two-input candidate tx that spends both outputs.
	candidateTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			buildVtxoInput(fundingPtx, outputA, outputIndexA, templateA),
			buildVtxoInput(fundingPtx, outputB, outputIndexB, templateB),
		},
		[]*wire.TxOut{{Value: outputA.Value + outputB.Value, PkScript: env.recipientPkScript}},
		env.checkpointScriptBytes,
	)
	require.NoError(t, err)
	require.Len(t, candidateTx.UnsignedTx.TxIn, 2)

	return candidateTx, checkpoints, fundingPtx
}

// executeAndExpectFailure asserts that local script execution fails with the expected error.
func executeAndExpectFailure(
	t *testing.T,
	candidateTx *psbt.Packet,
	introspectorPubKey *btcec.PublicKey,
	expectedErr string,
) {
	t.Helper()

	err := executeArkadeScripts(t, candidateTx, introspectorPubKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErr)
}

// submitAndExpectFailure checks that the introspector rejects the candidate tx.
func (env *crossInputTestEnv) submitAndExpectFailure(t *testing.T, candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
	t.Helper()

	encodedTx, err := candidateTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := env.bobWallet.SignTransaction(env.ctx, env.explorer, encodedTx)
	require.NoError(t, err)

	signedCheckpoints := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)

		signed, err := env.bobWallet.SignTransaction(env.ctx, env.explorer, encoded)
		require.NoError(t, err)
		signedCheckpoints = append(signedCheckpoints, signed)
	}

	_, _, err = env.introspectorClient.SubmitTx(env.ctx, signedTx, signedCheckpoints)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process transaction")
}

// submitAndFinalize submits the candidate tx once and verifies the result via the indexer.
func (env *crossInputTestEnv) submitAndFinalize(t *testing.T, candidateTx *psbt.Packet, checkpoints []*psbt.Packet) {
	t.Helper()

	// Step 1: Sign the candidate tx locally and sign every checkpoint.
	encodedTx, err := candidateTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := env.bobWallet.SignTransaction(env.ctx, env.explorer, encodedTx)
	require.NoError(t, err)

	signedCheckpoints := make([]string, 0, len(checkpoints))
	for _, checkpoint := range checkpoints {
		encoded, err := checkpoint.B64Encode()
		require.NoError(t, err)

		signed, err := env.bobWallet.SignTransaction(env.ctx, env.explorer, encoded)
		require.NoError(t, err)
		signedCheckpoints = append(signedCheckpoints, signed)
	}

	// Step 2: Submit once through introspector.
	_, _, err = env.introspectorClient.SubmitTx(env.ctx, signedTx, signedCheckpoints)
	require.NoError(t, err)

	// Step 3: Verify the finalized output via the indexer.
	opts := indexer.GetVtxosRequestOption{}
	err = opts.WithOutpoints([]types.Outpoint{{Txid: candidateTx.UnsignedTx.TxID(), VOut: 0}})
	require.NoError(t, err)

	vtxos, err := env.indexerSvc.GetVtxos(env.ctx, opts)
	require.NoError(t, err)
	require.Len(t, vtxos.Vtxos, 1)
	require.True(t, vtxos.Vtxos[0].Preconfirmed)
	require.False(t, vtxos.Vtxos[0].Spent)
}
