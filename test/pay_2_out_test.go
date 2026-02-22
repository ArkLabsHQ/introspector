package test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"context"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	mempoolexplorer "github.com/arkade-os/go-sdk/explorer/mempool"
	inmemorystoreconfig "github.com/arkade-os/go-sdk/store/inmemory"
	"github.com/arkade-os/go-sdk/types"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// uint64LE returns an 8-byte little-endian encoding of v.
func uint64LE(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// TestPayToTwoOutputs tests that an Arkade script can enforce payment to
// two specific outputs with correct addresses AND amounts.
//
// The script verifies:
//   - Output 0 scriptPubKey == Alice's taproot address, value == aliceAmount
//   - Output 1 scriptPubKey == Bob's taproot address, value == bobAmount
//
// Three cases are tested:
//  1. Invalid: wrong address on output 0 → failed to process transaction
//  2. Invalid: wrong amount on output 1 → failed to process transaction
//  3. Valid: both outputs correct → success
func TestPayToTwoOutputs(t *testing.T) {
	ctx := context.Background()
	alice, grpcAlice := setupArkSDK(t)
	defer grpcAlice.Close()

	// --- Bob wallet setup ---
	bobPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	configStore, err := inmemorystoreconfig.NewConfigStore()
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)

	bobWallet, err := singlekeywallet.NewBitcoinWallet(configStore, walletStore)
	require.NoError(t, err)

	_, err = bobWallet.Create(ctx, password, hex.EncodeToString(bobPrivKey.Serialize()))
	require.NoError(t, err)

	_, err = bobWallet.Unlock(ctx, password)
	require.NoError(t, err)

	bobPubKey := bobPrivKey.PubKey()

	// --- Fund Alice ---
	_, offchainAddr, boardingAddress, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceAddr, err := arklib.DecodeAddressV0(offchainAddr)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", boardingAddress)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	_, err = alice.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	// --- Constants ---
	const sendAmount = 10000
	const aliceAmount = 6000
	const bobAmount = 4000

	// --- Derive output scripts ---
	alicePkScript, err := script.P2TRScript(aliceAddr.VtxoTapKey)
	require.NoError(t, err)

	bobPkScript, err := txscript.PayToTaprootScript(bobPubKey)
	require.NoError(t, err)

	// --- Build Arkade script ---
	// Checks output 0 address, output 0 amount, output 1 address, output 1 amount.
	arkadeScript, err := txscript.NewScriptBuilder().
		// Check output 0 scriptPubKey == Alice
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // version == 1
		AddData(alicePkScript[2:]).   // witness program
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output 0 value == aliceAmount
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(uint64LE(aliceAmount)).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output 1 scriptPubKey == Bob
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY). // version == 1
		AddData(bobPkScript[2:]).     // witness program
		AddOp(arkade.OP_EQUALVERIFY).
		// Check output 1 value == bobAmount
		AddInt64(1).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddData(uint64LE(bobAmount)).
		AddOp(arkade.OP_EQUAL). // final check leaves result on stack
		Script()
	require.NoError(t, err)

	// --- Introspector client ---
	conn, err := grpc.NewClient("localhost:7073", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	introspectorClient := introspectorclient.NewGRPCClient(conn)

	introspectorInfo, err := introspectorClient.GetInfo(ctx)
	require.NoError(t, err)
	require.NotNil(t, introspectorInfo)

	publicKeyBytes, err := hex.DecodeString(introspectorInfo.SignerPublicKey)
	require.NoError(t, err)
	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	require.NoError(t, err)

	// --- VTXO with Arkade closure ---
	vtxoScript := script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPubKey,
					aliceAddr.Signer,
					arkade.ComputeArkadeScriptPublicKey(
						publicKey,
						arkade.ArkadeScriptHash(arkadeScript),
					),
				},
			},
		},
	}

	vtxoTapKey, vtxoTapTree, err := vtxoScript.TapTree()
	require.NoError(t, err)

	closure := vtxoScript.ForfeitClosures()[0]

	bobAddr := arklib.Address{
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

	bobAddrStr, err := bobAddr.EncodeV0()
	require.NoError(t, err)

	// --- Alice sends to contract ---
	txid, err := alice.SendOffChain(
		ctx, []types.Receiver{{To: bobAddrStr, Amount: sendAmount}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	// --- Find Bob's output in funding tx ---
	indexerSvc := setupIndexer(t)

	fundingTx, err := indexerSvc.GetVirtualTxs(ctx, []string{txid})
	require.NoError(t, err)
	require.NotEmpty(t, fundingTx)
	require.Len(t, fundingTx.Txs, 1)

	redeemPtx, err := psbt.NewFromRawBytes(strings.NewReader(fundingTx.Txs[0]), true)
	require.NoError(t, err)

	var bobOutput *wire.TxOut
	var bobOutputIndex uint32
	for i, out := range redeemPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript[2:], schnorr.SerializePubKey(bobAddr.VtxoTapKey)) {
			bobOutput = out
			bobOutputIndex = uint32(i)
			break
		}
	}
	require.NotNil(t, bobOutput)

	infos, err := grpcAlice.GetInfo(ctx)
	require.NoError(t, err)

	checkpointScriptBytes, err := hex.DecodeString(infos.CheckpointTapscript)
	require.NoError(t, err)

	vtxoInput := offchain.VtxoInput{
		Outpoint: &wire.OutPoint{
			Hash:  redeemPtx.UnsignedTx.TxHash(),
			Index: bobOutputIndex,
		},
		Tapscript:          tapscript,
		Amount:             bobOutput.Value,
		RevealedTapscripts: []string{hex.EncodeToString(arkadeTapscript)},
	}

	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)

	// ========================================
	// CASE 1: Invalid — wrong address on output 0
	// ========================================
	invalidAddrTx, invalidAddrCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: aliceAmount, PkScript: []byte{0x6a}}, // OP_RETURN, wrong address
			{Value: bobAmount, PkScript: bobPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	err = txutils.SetArkPsbtField(invalidAddrTx, 0, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	encodedInvalidAddrTx, err := invalidAddrTx.B64Encode()
	require.NoError(t, err)

	signedInvalidAddrTx, err := bobWallet.SignTransaction(ctx, explorer, encodedInvalidAddrTx)
	require.NoError(t, err)

	encodedInvalidAddrCheckpoints := make([]string, 0, len(invalidAddrCheckpoints))
	for _, cp := range invalidAddrCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedInvalidAddrCheckpoints = append(encodedInvalidAddrCheckpoints, encoded)
	}

	_, _, err = introspectorClient.SubmitTx(ctx, signedInvalidAddrTx, encodedInvalidAddrCheckpoints)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process transaction")

	// ========================================
	// CASE 2: Invalid — wrong amount on output 1
	// ========================================
	invalidAmtTx, invalidAmtCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: aliceAmount - 1, PkScript: alicePkScript}, // wrong amount (off by 1)
			{Value: bobAmount + 1, PkScript: bobPkScript},     // adjusted to keep sum equal
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	err = txutils.SetArkPsbtField(invalidAmtTx, 0, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	encodedInvalidAmtTx, err := invalidAmtTx.B64Encode()
	require.NoError(t, err)

	signedInvalidAmtTx, err := bobWallet.SignTransaction(ctx, explorer, encodedInvalidAmtTx)
	require.NoError(t, err)

	encodedInvalidAmtCheckpoints := make([]string, 0, len(invalidAmtCheckpoints))
	for _, cp := range invalidAmtCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedInvalidAmtCheckpoints = append(encodedInvalidAmtCheckpoints, encoded)
	}

	_, _, err = introspectorClient.SubmitTx(ctx, signedInvalidAmtTx, encodedInvalidAmtCheckpoints)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to process transaction")

	// ========================================
	// CASE 3: Valid — correct addresses and amounts
	// ========================================
	validTx, validCheckpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{vtxoInput},
		[]*wire.TxOut{
			{Value: aliceAmount, PkScript: alicePkScript},
			{Value: bobAmount, PkScript: bobPkScript},
		},
		checkpointScriptBytes,
	)
	require.NoError(t, err)

	err = txutils.SetArkPsbtField(validTx, 0, arkade.ArkadeScriptField, arkadeScript)
	require.NoError(t, err)

	encodedValidTx, err := validTx.B64Encode()
	require.NoError(t, err)

	signedTx, err := bobWallet.SignTransaction(ctx, explorer, encodedValidTx)
	require.NoError(t, err)

	encodedValidCheckpoints := make([]string, 0, len(validCheckpoints))
	for _, cp := range validCheckpoints {
		encoded, err := cp.B64Encode()
		require.NoError(t, err)
		encodedValidCheckpoints = append(encodedValidCheckpoints, encoded)
	}

	signedTx, signedByIntrospectorCheckpoints, err := introspectorClient.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	txid, _, signedByServerCheckpoints, err := grpcAlice.SubmitTx(ctx, signedTx, encodedValidCheckpoints)
	require.NoError(t, err)

	finalCheckpoints := make([]string, 0, len(signedByServerCheckpoints))
	for i, checkpoint := range signedByServerCheckpoints {
		finalCheckpoint, err := bobWallet.SignTransaction(ctx, explorer, checkpoint)
		require.NoError(t, err)

		byInterceptorCheckpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(signedByIntrospectorCheckpoints[i]), true)
		require.NoError(t, err)

		checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalCheckpoint), true)
		require.NoError(t, err)

		checkpointPtx.Inputs[0].TaprootScriptSpendSig = append(
			checkpointPtx.Inputs[0].TaprootScriptSpendSig,
			byInterceptorCheckpointPtx.Inputs[0].TaprootScriptSpendSig...,
		)

		finalCheckpoint, err = checkpointPtx.B64Encode()
		require.NoError(t, err)

		finalCheckpoints = append(finalCheckpoints, finalCheckpoint)
	}

	err = grpcAlice.FinalizeTx(ctx, txid, finalCheckpoints)
	require.NoError(t, err)
}
