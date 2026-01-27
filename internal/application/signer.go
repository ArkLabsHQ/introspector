package application

import (
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

type signer struct {
	secretKey *btcec.PrivateKey
}

func (s signer) signInput(ptx *psbt.Packet, inputIndex int, tweak []byte, prevoutFetcher txscript.PrevOutputFetcher) error {
	signingKey := arkade.ComputeArkadeScriptPrivateKey(s.secretKey, tweak)
	if len(ptx.Inputs) <= inputIndex || len(ptx.UnsignedTx.TxIn) <= inputIndex {
		return fmt.Errorf("input index out of range, cannot sign")
	}

	input := ptx.Inputs[inputIndex]
	// if not a taproot input, skip because arkd-wallet is taproot only accounts
	if !txscript.IsPayToTaproot(input.WitnessUtxo.PkScript) {
		return fmt.Errorf("not a taproot input, cannot sign")
	}

	if len(input.TaprootLeafScript) == 0 || input.TaprootLeafScript[0] == nil {
		return fmt.Errorf("no taproot leaf script, cannot sign")
	}

	tapLeaf := txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)
	txSigHashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	signature, err := txscript.RawTxInTapscriptSignature(
		ptx.UnsignedTx, txSigHashes, inputIndex, input.WitnessUtxo.Value,
		input.WitnessUtxo.PkScript, tapLeaf, input.SighashType, signingKey,
	)
	if err != nil {
		return fmt.Errorf("failed to sign taproot leaf: %w", err)
	}

	leafHash := tapLeaf.TapHash()

	ptx.Inputs[inputIndex].TaprootScriptSpendSig = append(ptx.Inputs[inputIndex].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		Signature:   signature[:64], // remove the last byte (sig hash type) because signature is already encoded
		XOnlyPubKey: schnorr.SerializePubKey(signingKey.PubKey()),
		LeafHash:    leafHash[:],
		SigHash:     input.SighashType,
	})

	return nil
}
