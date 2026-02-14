package test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	introspectorclient "github.com/ArkLabsHQ/introspector/pkg/client"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arksdk "github.com/arkade-os/go-sdk"
	inmemorystoreconfig "github.com/arkade-os/go-sdk/store/inmemory"
	"github.com/arkade-os/go-sdk/wallet"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// setupBobWallet creates and unlocks a new wallet for Bob
func setupBobWallet(t *testing.T, ctx context.Context) (wallet.WalletService, *btcec.PrivateKey, *btcec.PublicKey) {
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

	return bobWallet, bobPrivKey, bobPrivKey.PubKey()
}

// fundAndSettleAlice funds alice's account via boarding and settles
func fundAndSettleAlice(t *testing.T, ctx context.Context, alice arksdk.ArkClient) *arklib.Address {
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

	return aliceAddr
}

// createAssetPacket creates a simple asset issuance packet with one output
func createAssetPacket(t *testing.T, vout uint16, amount uint64) asset.Packet {
	assetGroup, err := asset.NewAssetGroup(
		nil,                  // nil AssetId means issuance (will use current tx hash)
		nil,                  // no control asset
		[]asset.AssetInput{}, // no inputs (issuance)
		[]asset.AssetOutput{
			{
				Vout:   vout,
				Amount: amount,
			},
		},
		[]asset.Metadata{}, // no metadata
	)
	require.NoError(t, err)

	assetPacket, err := asset.NewPacket([]asset.AssetGroup{*assetGroup})
	require.NoError(t, err)

	return assetPacket
}

// createArkadeScriptWithAssetChecks creates an arkade script that verifies:
// - Output goes to specified address
// - Exactly 1 asset group
// - Asset output sum equals expected amount
func createArkadeScriptWithAssetChecks(t *testing.T, alicePkScript []byte, assetAmount int64) []byte {
	arkadeScript, err := txscript.NewScriptBuilder().
		// Check output 0 goes to alice's address
		AddInt64(0).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(alicePkScript[2:]). // only witness program
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: 1 asset group
		AddOp(arkade.OP_INSPECTNUMASSETGROUPS).
		AddInt64(1).
		AddOp(arkade.OP_EQUALVERIFY).
		// Check: sum of outputs for group 0 equals assetAmount
		AddInt64(0). // group index
		AddInt64(1). // source = outputs
		AddOp(arkade.OP_INSPECTASSETGROUPSUM).
		AddInt64(assetAmount).
		AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)

	return arkadeScript
}

// setupIntrospectorClient creates and returns an introspector client and its signer public key
func setupIntrospectorClient(t *testing.T, ctx context.Context) (introspectorclient.TransportClient, *btcec.PublicKey, *grpc.ClientConn) {
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

	return introspectorClient, publicKey, conn
}

// createVtxoScriptWithArkade creates a vtxo script with a multisig closure containing the arkade script pubkey
func createVtxoScriptWithArkade(bobPubKey, aliceSigner, introspectorPubKey *btcec.PublicKey, arkadeScriptHash []byte) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPubKey,
					aliceSigner,
					arkade.ComputeArkadeScriptPublicKey(introspectorPubKey, arkadeScriptHash),
				},
			},
		},
	}
}

// createVtxoScriptWithArkadeAndCSV creates a vtxo script with arkade closure + CSV closure
func createVtxoScriptWithArkadeAndCSV(bobPubKey, aliceSigner, introspectorPubKey *btcec.PublicKey, arkadeScriptHash []byte) script.TapscriptsVtxoScript {
	return script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					bobPubKey,
					aliceSigner,
					arkade.ComputeArkadeScriptPublicKey(introspectorPubKey, arkadeScriptHash),
				},
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{
						bobPubKey,
						aliceSigner,
					},
				},
				Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512 * 10},
			},
		},
	}
}
