package application

import (
	"bytes"
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type arkadeScript struct {
	script  []byte
	hash    []byte
	witness wire.TxWitness
	pubkey  *btcec.PublicKey
	tapLeaf txscript.TapLeaf
}

func readArkadeScript(ptx *psbt.Packet, inputIndex int, signerPublicKey *btcec.PublicKey) (*arkadeScript, error) {
	if len(ptx.Inputs) <= inputIndex {
		return nil, fmt.Errorf("input index out of range")
	}

	input := ptx.Inputs[inputIndex]
	if len(input.TaprootLeafScript) == 0 {
		return nil, fmt.Errorf("input does not specify any TaprootLeafScript")
	}

	spendingTapscript := input.TaprootLeafScript[0]
	if spendingTapscript == nil {
		return nil, fmt.Errorf("input does not specify any TaprootLeafScript")
	}

	arkadeScriptsFields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.ArkadeScriptField)
	if err != nil {
		return nil, fmt.Errorf("unexpected error while getting arkade script fields: %w", err)
	}

	if len(arkadeScriptsFields) == 0 {
		return nil, fmt.Errorf("input does not specify any ArkadeScript")
	}

	// TODO allow multiple scripts ?
	arkadescript := arkadeScriptsFields[0]
	scriptHash := arkade.ArkadeScriptHash(arkadescript)
	expectedPublicKey := arkade.ComputeArkadeScriptPublicKey(signerPublicKey, scriptHash)
	expectedPublicKeyXonly := schnorr.SerializePubKey(expectedPublicKey)

	// TODO: allow any type of closure (condition, cltv ...)
	var tapscript scriptlib.MultisigClosure
	valid, err := tapscript.Decode(spendingTapscript.Script)
	if err != nil {
		return nil, fmt.Errorf("unexpected error while decoding tapscript: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("spendingtapscript is not a MultisigClosure")
	}

	found := false

	for _, pubkey := range tapscript.PubKeys {
		xonly := schnorr.SerializePubKey(pubkey)
		if bytes.Equal(xonly, expectedPublicKeyXonly) {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("tweaked arkade script public key not found in tapscript")
	}

	arkadeScriptWitnessFields, err := txutils.GetArkPsbtFields(ptx, inputIndex, arkade.ArkadeScriptWitnessField)
	if err != nil {
		return nil, fmt.Errorf("unexpected error while getting arkade script witness fields: %w", err)
	}

	arkadeScriptWitness := make(wire.TxWitness, 0)
	if len(arkadeScriptWitnessFields) > 0 {
		arkadeScriptWitness = arkadeScriptWitnessFields[0]
	}

	return &arkadeScript{
		script:  arkadescript,
		hash:    scriptHash,
		witness: arkadeScriptWitness,
		pubkey:  expectedPublicKey,
		tapLeaf: txscript.NewBaseTapLeaf(spendingTapscript.Script),
	}, nil
}

func (s arkadeScript) execute(spendingTx *wire.MsgTx, prevoutFetcher txscript.PrevOutputFetcher, inputIndex int) error {
	engine, err := arkade.NewEngine(
		s.script,
		spendingTx,
		inputIndex,
		txscript.StandardVerifyFlags,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(spendingTx, prevoutFetcher),
		0, // TODO : add input amount if need CHECKSIG in custom script?
		prevoutFetcher,
	)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Parse asset packet from transaction if present
	assetPacket, err := asset.NewPacketFromTx(spendingTx)
	if err == nil {
		// Asset packet found, set it on the engine for introspection opcodes
		engine.SetAssetPacket(assetPacket)
	}
	// If error, packet is not present - this is okay, just don't set it

	if len(s.witness) > 0 {
		engine.SetStack(s.witness)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("failed to execute arkade script: %w", err)
	}

	return nil
}
