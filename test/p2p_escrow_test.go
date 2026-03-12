package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"context"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// escrowParams holds the contract parameters for a P2P exchange escrow.
type escrowParams struct {
	sellerPubKey *btcec.PublicKey
	buyerPubKey  *btcec.PublicKey
	serverPubKey *btcec.PublicKey
	feeSpk       []byte // fee output scriptPubKey
	minFeeSats   uint64
	csvTimeout   int64
}

// tradeID computes the deterministic trade identifier:
// SHA256(seller_pk || buyer_pk || server_pk)
func (p *escrowParams) tradeID() []byte {
	h := sha256.New()
	h.Write(schnorr.SerializePubKey(p.sellerPubKey))
	h.Write(schnorr.SerializePubKey(p.buyerPubKey))
	h.Write(schnorr.SerializePubKey(p.serverPubKey))
	sum := h.Sum(nil)
	return sum
}

// releaseMsg returns the 32-byte RELEASE oracle message hash:
// SHA256(0x01 || trade_id).
func (p *escrowParams) releaseMsg() []byte {
	preimage := make([]byte, 33)
	preimage[0] = 0x01
	copy(preimage[1:], p.tradeID())
	hash := sha256.Sum256(preimage)
	return hash[:]
}

// cancelMsg returns the 32-byte CANCEL oracle message hash:
// SHA256(0x02 || trade_id).
func (p *escrowParams) cancelMsg() []byte {
	preimage := make([]byte, 33)
	preimage[0] = 0x02
	copy(preimage[1:], p.tradeID())
	hash := sha256.Sum256(preimage)
	return hash[:]
}

// buildLeaf0SellerConfirm builds the Arkade script for Leaf 0:
// Seller attests RELEASE via CSFS, fee output enforced via introspection.
//
// Stack (witness): <seller_csfs_sig> <RELEASE_msg>
// Script:
//
//	<seller_pk> OP_CHECKSIGFROMSTACK OP_VERIFY   # seller attests RELEASE
//	OP_INSPECTNUMINPUTS 1 OP_EQUALVERIFY         # single input only
//	1 OP_INSPECTOUTPUTSCRIPTPUBKEY               # output[1] = fee
//	  <fee_version> OP_EQUALVERIFY
//	  <fee_program> OP_EQUALVERIFY
//	1 OP_INSPECTOUTPUTVALUE
//	  <min_fee_le64> OP_GREATERTHANOREQUAL64     # fee >= min
func buildLeaf0SellerConfirm(p *escrowParams) ([]byte, error) {
	feeVersion, feeProgram, err := extractWitnessInfo(p.feeSpk)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().
		// CSFS: verify seller attests RELEASE
		AddData(schnorr.SerializePubKey(p.sellerPubKey)).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		AddOp(arkade.OP_VERIFY).
		// Enforce single input
		AddOp(arkade.OP_INSPECTNUMINPUTS).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output[1] scriptPubKey == fee address
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(int64(feeVersion)).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(feeProgram).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output[1] value >= minFeeSats
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(uint64LE(p.minFeeSats)).
		AddOp(arkade.OP_GREATERTHANOREQUAL64).
		Script()
}

// buildLeaf1ArbitratorToBuyer builds the Arkade script for Leaf 1:
// Server attests RELEASE via CSFS, fee output enforced.
// Same structure as Leaf 0 but uses server pubkey instead of seller.
//
// Stack (witness): <server_csfs_sig> <RELEASE_msg>
func buildLeaf1ArbitratorToBuyer(p *escrowParams) ([]byte, error) {
	feeVersion, feeProgram, err := extractWitnessInfo(p.feeSpk)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().
		// CSFS: verify server attests RELEASE
		AddData(schnorr.SerializePubKey(p.serverPubKey)).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		AddOp(arkade.OP_VERIFY).
		// Enforce single input
		AddOp(arkade.OP_INSPECTNUMINPUTS).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output[1] scriptPubKey == fee address
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(int64(feeVersion)).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(feeProgram).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output[1] value >= minFeeSats
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(uint64LE(p.minFeeSats)).
		AddOp(arkade.OP_GREATERTHANOREQUAL64).
		Script()
}

// buildLeaf2BuyerRefund builds the Arkade script for Leaf 2:
// Buyer attests CANCEL via CSFS. No fee. Destinations free.
//
// Stack (witness): <buyer_csfs_sig> <CANCEL_msg>
func buildLeaf2BuyerRefund(p *escrowParams) ([]byte, error) {
	return txscript.NewScriptBuilder().
		// CSFS: verify buyer attests CANCEL
		AddData(schnorr.SerializePubKey(p.buyerPubKey)).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		Script()
}

// buildLeaf3ArbitratorToSeller builds the Arkade script for Leaf 3:
// Server attests CANCEL via CSFS. No fee. Destinations free.
//
// Stack (witness): <server_csfs_sig> <CANCEL_msg>
func buildLeaf3ArbitratorToSeller(p *escrowParams) ([]byte, error) {
	return txscript.NewScriptBuilder().
		// CSFS: verify server attests CANCEL
		AddData(schnorr.SerializePubKey(p.serverPubKey)).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).
		Script()
}

// buildLeaf5TopupPath builds the Arkade script for Leaf 5:
// Recursive covenant — output[0] must carry the same scriptPubKey with
// strictly more value. No signatures required.
//
// Stack (witness): empty
func buildLeaf5TopupPath() ([]byte, error) {
	return txscript.NewScriptBuilder().
		// output[0].scriptPubKey == input[current].scriptPubKey
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).AddOp(arkade.OP_EQUALVERIFY). // segwit v1
		AddOp(arkade.OP_EQUALVERIFY).                    // witness programs match
		// output[0].value > input[current].value
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		// stack: [input_value, output_value]
		// OP_GREATERTHAN64 pops b then a, checks a < b (i.e. input < output)
		AddOp(arkade.OP_LESSTHAN64).
		Script()
}

// extractWitnessInfo extracts the segwit version and witness program from a scriptPubKey.
func extractWitnessInfo(spk []byte) (int, []byte, error) {
	version, program, err := txscript.ExtractWitnessProgramInfo(spk)
	if err != nil {
		return 0, nil, err
	}
	return version, program, nil
}

// serializeWitness serializes witness stack items using the wire TxWitness format.
func serializeWitness(items ...[]byte) []byte {
	var buf bytes.Buffer
	witness := wire.TxWitness(items)
	if err := psbt.WriteTxWitness(&buf, witness); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// signCSFS creates a Schnorr signature over the given message with the private key.
func signCSFS(privKey *btcec.PrivateKey, message []byte) []byte {
	sig, err := schnorr.Sign(privKey, message)
	if err != nil {
		panic(err)
	}
	return sig.Serialize()
}

// TestP2PEscrowSellerConfirm tests Leaf 0: seller attests RELEASE, buyer claims.
// Verifies:
//   - Valid: seller CSFS attestation + correct fee output → script passes
//   - Invalid: wrong CSFS message → script fails
//   - Invalid: fee too low → script fails
//   - Invalid: wrong fee address → script fails
func TestP2PEscrowSellerConfirm(t *testing.T) {
	ctx := context.Background()

	alice, _, alicePubKey, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcAlice.Close() })

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcBob.Close() })

	const escrowAmount = int64(50000)
	const feeAmount = uint64(1000)

	_ = fundAndSettleAlice(t, ctx, alice, escrowAmount)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	bobAddr, err := arklib.DecodeAddressV0(bobOffchainAddr)
	require.NoError(t, err)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	// Generate keys for the escrow roles
	sellerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Fee address (use alice's taproot key)
	feePkScript, err := txscript.PayToTaprootScript(alicePubKey)
	require.NoError(t, err)

	params := &escrowParams{
		sellerPubKey: sellerPrivKey.PubKey(),
		buyerPubKey:  bobPubKey,
		serverPubKey: serverPrivKey.PubKey(),
		feeSpk:       feePkScript,
		minFeeSats:   feeAmount,
		csvTimeout:   144,
	}

	// Build the Leaf 0 Arkade script
	arkadeScript, err := buildLeaf0SellerConfirm(params)
	require.NoError(t, err)

	// Create VTXO with this Arkade script
	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey,
		bobAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	escrowAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     bobAddr.Signer,
	}

	escrowAddrStr, err := escrowAddr.EncodeV0()
	require.NoError(t, err)

	// Alice funds the escrow
	fundingTxid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: escrowAddrStr, Amount: uint64(escrowAmount)}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	indexerSvc := setupIndexer(t)
	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	var escrowOutput *wire.TxOut
	var escrowOutputIndex uint32
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(escrowAddr.VtxoTapKey)) {
			escrowOutput = out
			escrowOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, escrowOutput)

	closure := vtxoScript.ForfeitClosures()[0]
	closureTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscript := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: escrowOutputIndex,
		},
		Tapscript:          tapscript,
		Amount:             escrowOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(closureTapscript)},
	}

	// Buyer's receive address (any address they choose)
	buyerRecvPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	buyerRecvPkScript, err := txscript.PayToTaprootScript(buyerRecvPrivKey.PubKey())
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	releaseMsg := params.releaseMsg()

	submitAndExpectFailure := func(outputs []*wire.TxOut, witness []byte) {
		candidateTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{vtxoInput},
			outputs,
			checkpointScriptBytes,
		)
		require.NoError(t, err)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: arkadeScript, Witness: witness},
		})

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	// ========================================
	// CASE 1: Invalid — wrong CSFS message (CANCEL instead of RELEASE)
	// ========================================
	wrongMsg := params.cancelMsg()
	wrongMsgSig := signCSFS(sellerPrivKey, wrongMsg)
	submitAndExpectFailure(
		[]*wire.TxOut{
			{Value: escrowOutput.Value - int64(feeAmount), PkScript: buyerRecvPkScript},
			{Value: int64(feeAmount), PkScript: feePkScript},
		},
		serializeWitness(wrongMsgSig, wrongMsg),
	)

	// ========================================
	// CASE 2: Invalid — fee too low
	// ========================================
	validSig := signCSFS(sellerPrivKey, releaseMsg)
	submitAndExpectFailure(
		[]*wire.TxOut{
			{Value: escrowOutput.Value - int64(feeAmount/2), PkScript: buyerRecvPkScript},
			{Value: int64(feeAmount / 2), PkScript: feePkScript}, // fee too low
		},
		serializeWitness(validSig, releaseMsg),
	)

	// ========================================
	// CASE 3: Invalid — wrong fee address
	// ========================================
	wrongFeePkScript, err := txscript.PayToTaprootScript(buyerRecvPrivKey.PubKey())
	require.NoError(t, err)
	submitAndExpectFailure(
		[]*wire.TxOut{
			{Value: escrowOutput.Value - int64(feeAmount), PkScript: buyerRecvPkScript},
			{Value: int64(feeAmount), PkScript: wrongFeePkScript}, // wrong address
		},
		serializeWitness(validSig, releaseMsg),
	)

	// ========================================
	// CASE 4: Valid — correct seller attestation + fee
	// ========================================
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: escrowOutput.Value - int64(feeAmount), PkScript: buyerRecvPkScript},
			{Value: int64(feeAmount), PkScript: feePkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: serializeWitness(validSig, releaseMsg)},
	})

	// Debug execute to verify locally first
	require.NoError(t, debugExecuteArkadeScripts(t, validTx, introspectorPubKey))

	// Submit to introspector + finalize
	encodedTx, err := validTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)

	encodedCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

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

// TestP2PEscrowArbitratorToBuyer tests Leaf 1: server attests RELEASE, buyer claims.
func TestP2PEscrowArbitratorToBuyer(t *testing.T) {
	ctx := context.Background()

	alice, _, alicePubKey, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcAlice.Close() })

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcBob.Close() })

	const escrowAmount = int64(50000)
	const feeAmount = uint64(1000)

	_ = fundAndSettleAlice(t, ctx, alice, escrowAmount)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	bobAddr, err := arklib.DecodeAddressV0(bobOffchainAddr)
	require.NoError(t, err)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	sellerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	feePkScript, err := txscript.PayToTaprootScript(alicePubKey)
	require.NoError(t, err)

	params := &escrowParams{
		sellerPubKey: sellerPrivKey.PubKey(),
		buyerPubKey:  bobPubKey,
		serverPubKey: serverPrivKey.PubKey(),
		feeSpk:       feePkScript,
		minFeeSats:   feeAmount,
		csvTimeout:   144,
	}

	arkadeScript, err := buildLeaf1ArbitratorToBuyer(params)
	require.NoError(t, err)

	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, bobAddr.Signer, introspectorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	escrowAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     bobAddr.Signer,
	}
	escrowAddrStr, err := escrowAddr.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: escrowAddrStr, Amount: uint64(escrowAmount)}},
	)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)
	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	var escrowOutput *wire.TxOut
	var escrowOutputIndex uint32
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(escrowAddr.VtxoTapKey)) {
			escrowOutput = out
			escrowOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, escrowOutput)

	closure := vtxoScript.ForfeitClosures()[0]
	closureTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: escrowOutputIndex,
		},
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		},
		Amount:             escrowOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(closureTapscript)},
	}

	buyerRecvPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	buyerRecvPkScript, err := txscript.PayToTaprootScript(buyerRecvPrivKey.PubKey())
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	releaseMsg := params.releaseMsg()

	// Valid: server attests RELEASE + correct fee
	serverSig := signCSFS(serverPrivKey, releaseMsg)

	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: escrowOutput.Value - int64(feeAmount), PkScript: buyerRecvPkScript},
			{Value: int64(feeAmount), PkScript: feePkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: serializeWitness(serverSig, releaseMsg)},
	})

	require.NoError(t, debugExecuteArkadeScripts(t, validTx, introspectorPubKey))

	encodedTx, err := validTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)

	encodedCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

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

// TestP2PEscrowArbitratorToSeller tests Leaf 3: server attests CANCEL, seller reclaims.
func TestP2PEscrowArbitratorToSeller(t *testing.T) {
	ctx := context.Background()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcAlice.Close() })

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcBob.Close() })

	const escrowAmount = int64(50000)

	_ = fundAndSettleAlice(t, ctx, alice, escrowAmount)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	bobAddr, err := arklib.DecodeAddressV0(bobOffchainAddr)
	require.NoError(t, err)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	sellerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	params := &escrowParams{
		sellerPubKey: sellerPrivKey.PubKey(),
		buyerPubKey:  bobPubKey,
		serverPubKey: serverPrivKey.PubKey(),
		feeSpk:       []byte{0x6a}, // unused for this leaf
		minFeeSats:   1000,
		csvTimeout:   144,
	}

	arkadeScript, err := buildLeaf3ArbitratorToSeller(params)
	require.NoError(t, err)

	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey, bobAddr.Signer, introspectorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	escrowAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     bobAddr.Signer,
	}
	escrowAddrStr, err := escrowAddr.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: escrowAddrStr, Amount: uint64(escrowAmount)}},
	)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)
	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	var escrowOutput *wire.TxOut
	var escrowOutputIndex uint32
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(escrowAddr.VtxoTapKey)) {
			escrowOutput = out
			escrowOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, escrowOutput)

	closure := vtxoScript.ForfeitClosures()[0]
	closureTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: escrowOutputIndex,
		},
		Tapscript: &waddrmgr.Tapscript{
			ControlBlock:   ctrlBlock,
			RevealedScript: merkleProof.Script,
		},
		Amount:             escrowOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(closureTapscript)},
	}

	sellerRecvPkScript, err := txscript.PayToTaprootScript(sellerPrivKey.PubKey())
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	cancelMsg := params.cancelMsg()

	// Valid: server attests CANCEL, full refund to seller
	serverCancelSig := signCSFS(serverPrivKey, cancelMsg)

	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: escrowOutput.Value, PkScript: sellerRecvPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: serializeWitness(serverCancelSig, cancelMsg)},
	})

	require.NoError(t, debugExecuteArkadeScripts(t, validTx, introspectorPubKey))

	encodedTx, err := validTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)

	encodedCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

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

// TestP2PEscrowBuyerRefund tests Leaf 2: buyer attests CANCEL, seller reclaims.
func TestP2PEscrowBuyerRefund(t *testing.T) {
	ctx := context.Background()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcAlice.Close() })

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcBob.Close() })

	const escrowAmount = int64(50000)

	_ = fundAndSettleAlice(t, ctx, alice, escrowAmount)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	bobAddr, err := arklib.DecodeAddressV0(bobOffchainAddr)
	require.NoError(t, err)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	sellerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	buyerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	serverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// For this test, bob acts as the counterparty managing the VTXO,
	// and buyer/seller are oracle signers
	feePkScript, err := txscript.PayToTaprootScript(sellerPrivKey.PubKey())
	require.NoError(t, err)

	params := &escrowParams{
		sellerPubKey: sellerPrivKey.PubKey(),
		buyerPubKey:  buyerPrivKey.PubKey(),
		serverPubKey: serverPrivKey.PubKey(),
		feeSpk:       feePkScript,
		minFeeSats:   1000,
		csvTimeout:   144,
	}

	arkadeScript, err := buildLeaf2BuyerRefund(params)
	require.NoError(t, err)

	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey,
		bobAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	escrowAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     bobAddr.Signer,
	}

	escrowAddrStr, err := escrowAddr.EncodeV0()
	require.NoError(t, err)

	fundingTxid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: escrowAddrStr, Amount: uint64(escrowAmount)}},
	)
	require.NoError(t, err)

	indexerSvc := setupIndexer(t)
	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	var escrowOutput *wire.TxOut
	var escrowOutputIndex uint32
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(escrowAddr.VtxoTapKey)) {
			escrowOutput = out
			escrowOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, escrowOutput)

	closure := vtxoScript.ForfeitClosures()[0]
	closureTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscriptObj := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: escrowOutputIndex,
		},
		Tapscript:          tapscriptObj,
		Amount:             escrowOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(closureTapscript)},
	}

	sellerRecvPkScript, err := txscript.PayToTaprootScript(sellerPrivKey.PubKey())
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	cancelMsg := params.cancelMsg()

	// ========================================
	// CASE 1: Invalid — wrong party attests (seller instead of buyer)
	// ========================================
	wrongPartySig := signCSFS(sellerPrivKey, cancelMsg)
	candidateTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: escrowOutput.Value, PkScript: sellerRecvPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: serializeWitness(wrongPartySig, cancelMsg)},
	})

	encodedTx, err := candidateTx.B64Encode()
	require.NoError(t, err)
	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)

	encodedCheckpoints := make([]string, 0, len(checkpoints))
	for _, cp := range checkpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

	_, _, err = introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process transaction")

	// ========================================
	// CASE 2: Valid — buyer attests CANCEL, full refund to seller
	// ========================================
	buyerCancelSig := signCSFS(buyerPrivKey, cancelMsg)

	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: escrowOutput.Value, PkScript: sellerRecvPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript, Witness: serializeWitness(buyerCancelSig, cancelMsg)},
	})

	require.NoError(t, debugExecuteArkadeScripts(t, validTx, introspectorPubKey))

	encodedTx, err = validTx.B64Encode()
	require.NoError(t, err)
	signedTx, err = bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)

	encodedCheckpoints = make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

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

// TestP2PEscrowTopupPath tests Leaf 5: recursive covenant top-up.
// Anyone can grow the escrow — output[0] must carry the same scriptPubKey
// with strictly more value than the input.
func TestP2PEscrowTopupPath(t *testing.T) {
	ctx := context.Background()

	alice, _, _, grpcAlice := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcAlice.Close() })

	bob, bobWallet, bobPubKey, grpcBob := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { grpcBob.Close() })

	const escrowAmount = int64(30000)

	_ = fundAndSettleAlice(t, ctx, alice, escrowAmount+50000)

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	bobAddr, err := arklib.DecodeAddressV0(bobOffchainAddr)
	require.NoError(t, err)

	introspectorClient, introspectorPubKey, conn := setupIntrospectorClient(t, ctx)
	t.Cleanup(func() {
		//nolint:errcheck
		conn.Close()
	})

	// Build the topup Arkade script
	arkadeScript, err := buildLeaf5TopupPath()
	require.NoError(t, err)

	vtxoScript := createVtxoScriptWithArkadeScript(
		bobPubKey,
		bobAddr.Signer,
		introspectorPubKey,
		arkade.ArkadeScriptHash(arkadeScript),
	)

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	escrowAddr := arklib.Address{
		HRP:        "tark",
		VtxoTapKey: vtxoTapKey,
		Signer:     bobAddr.Signer,
	}

	escrowAddrStr, err := escrowAddr.EncodeV0()
	require.NoError(t, err)

	inputPkScript, err := script.P2TRScript(escrowAddr.VtxoTapKey)
	require.NoError(t, err)

	// Alice sends initial escrow amount
	fundingTxid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: escrowAddrStr, Amount: uint64(escrowAmount)}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, fundingTxid)

	indexerSvc := setupIndexer(t)
	fundingTxs, err := indexerSvc.GetVirtualTxs(ctx, []string{fundingTxid})
	require.NoError(t, err)
	require.Len(t, fundingTxs.Txs, 1)

	fundingPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTxs.Txs[0]), true)
	require.NoError(t, err)

	var escrowOutput *wire.TxOut
	var escrowOutputIndex uint32
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(escrowAddr.VtxoTapKey)) {
			escrowOutput = out
			escrowOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, escrowOutput)

	closure := vtxoScript.ForfeitClosures()[0]
	closureTapscript, err := closure.Script()
	require.NoError(t, err)

	merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
		txscript.NewBaseTapLeaf(closureTapscript).TapHash(),
	)
	require.NoError(t, err)

	ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
	require.NoError(t, err)

	tapscriptObj := &waddrmgr.Tapscript{
		ControlBlock:   ctrlBlock,
		RevealedScript: merkleProof.Script,
	}

	infos, err := grpcBob.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  fundingPtx.UnsignedTx.TxHash(),
			Index: escrowOutputIndex,
		},
		Tapscript:          tapscriptObj,
		Amount:             escrowOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(closureTapscript)},
	}

	changePkScript, err := txscript.PayToTaprootScript(bobPubKey)
	require.NoError(t, err)

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	submitAndExpectFailure := func(outputs []*wire.TxOut) {
		candidateTx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{vtxoInput},
			outputs,
			checkpointScriptBytes,
		)
		require.NoError(t, err)

		addIntrospectorPacket(t, candidateTx, []arkade.IntrospectorEntry{
			{Vin: 0, Script: arkadeScript},
		})

		encodedTx, err := candidateTx.B64Encode()
		require.NoError(t, err)

		signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
		require.NoError(t, err)

		encodedCheckpoints := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			encoded, err := cp.B64Encode()
			require.NoError(t, err)
			encodedCheckpoints = append(encodedCheckpoints, encoded)
		}

		_, _, err = introspectorClient.SubmitTx(ctx, signedTx, encodedCheckpoints)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to process transaction")
	}

	// ========================================
	// CASE 1: Invalid — output value not greater than input
	// ========================================
	submitAndExpectFailure([]*wire.TxOut{
		{Value: escrowOutput.Value, PkScript: inputPkScript}, // same value, not greater
		{Value: 0, PkScript: changePkScript},
	})

	// ========================================
	// CASE 2: Invalid — wrong scriptPubKey on output[0]
	// ========================================
	submitAndExpectFailure([]*wire.TxOut{
		{Value: escrowOutput.Value + 10000, PkScript: changePkScript}, // wrong spk
	})

	// ========================================
	// CASE 3: Valid — output[0] has same scriptPubKey with more value
	// ========================================
	topupAmount := int64(10000)
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: escrowOutput.Value + topupAmount, PkScript: inputPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	addIntrospectorPacket(t, validTx, []arkade.IntrospectorEntry{
		{Vin: 0, Script: arkadeScript},
	})

	require.NoError(t, debugExecuteArkadeScripts(t, validTx, introspectorPubKey))

	encodedTx, err := validTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedTx)
	require.NoError(t, err)

	encodedCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedCheckpoints = append(encodedCheckpoints, encoded)
	}

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
