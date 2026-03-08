package application

import (
	"bytes"
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
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

// readArkadeScript reads an arkade script from an IntrospectorEntry and validates
// it against the tapscript in the PSBT input. The entry contains the script and
// witness data extracted from the Introspector Packet (OP_RETURN TLV).
func readArkadeScript(ptx *psbt.Packet, inputIndex int, signerPublicKey *btcec.PublicKey, entry arkade.IntrospectorEntry) (*arkadeScript, error) {
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

	scriptHash := arkade.ArkadeScriptHash(entry.Script)
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

	arkadeScriptWitness := make(wire.TxWitness, 0)
	if len(entry.Witness) > 0 {
		witness, err := txutils.ReadTxWitness(entry.Witness)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize witness: %w", err)
		}
		arkadeScriptWitness = witness
	}

	return &arkadeScript{
		script:  entry.Script,
		hash:    scriptHash,
		witness: arkadeScriptWitness,
		pubkey:  expectedPublicKey,
		tapLeaf: txscript.NewBaseTapLeaf(spendingTapscript.Script),
	}, nil
}

func (s arkadeScript) execute(spendingTx *wire.MsgTx, prevoutFetcher txscript.PrevOutputFetcher, inputIndex int, packet *arkade.IntrospectorPacket) error {
	prevOut := prevoutFetcher.FetchPrevOutput(spendingTx.TxIn[inputIndex].PreviousOutPoint)
	inputAmount := int64(0)
	if prevOut != nil {
		inputAmount = prevOut.Value
	}

	engine, err := arkade.NewEngine(
		s.script,
		spendingTx,
		inputIndex,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(spendingTx, prevoutFetcher),
		inputAmount,
		prevoutFetcher,
	)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}

	// Parse asset packet from transaction extension if present
	ext, err := extension.NewExtensionFromTx(spendingTx)
	if err == nil {
		if ap := ext.GetAssetPacket(); ap != nil {
			engine.SetAssetPacket(ap)
		}
	}
	// If error, extension is not present - this is okay, just don't set it

	if packet != nil {
		engine.SetIntrospectorPacket(packet)
	}

	if len(s.witness) > 0 {
		engine.SetStack(s.witness)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("failed to execute arkade script: %w", err)
	}

	return nil
}
