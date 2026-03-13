package arkade

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// closurePubKeys extracts the PubKeys from any closure type that embeds MultisigClosure.
func closurePubKeys(c scriptlib.Closure) []*btcec.PublicKey {
	switch v := c.(type) {
	case *scriptlib.MultisigClosure:
		return v.PubKeys
	case *scriptlib.CLTVMultisigClosure:
		return v.PubKeys
	case *scriptlib.CSVMultisigClosure:
		return v.PubKeys
	case *scriptlib.ConditionMultisigClosure:
		return v.PubKeys
	case *scriptlib.ConditionCSVMultisigClosure:
		return v.PubKeys
	default:
		return nil
	}
}

type ArkadeScript struct {
	script  []byte
	hash    []byte
	witness wire.TxWitness
	pubkey  *btcec.PublicKey
	tapLeaf txscript.TapLeaf
}

type ExecuteOption func(*Engine)

func WithDebugCallback(callback func(*StepInfo, *Engine) error) ExecuteOption {
	return func(engine *Engine) {
		engine.stepCallback = func(step *StepInfo) error {
			return callback(step, engine)
		}
	}
}

func ReadArkadeScript(ptx *psbt.Packet, inputIndex int, signerPublicKey *btcec.PublicKey, entry IntrospectorEntry) (*ArkadeScript, error) {
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

	scriptHash := ArkadeScriptHash(entry.Script)
	expectedPublicKey := ComputeArkadeScriptPublicKey(signerPublicKey, scriptHash)
	expectedPublicKeyXonly := schnorr.SerializePubKey(expectedPublicKey)

	closure, err := scriptlib.DecodeClosure(spendingTapscript.Script)
	if err != nil {
		return nil, fmt.Errorf("unexpected error while decoding tapscript: %w", err)
	}

	pubkeys := closurePubKeys(closure)
	if pubkeys == nil {
		return nil, fmt.Errorf("decoded closure has no public keys")
	}

	found := false
	for _, pubkey := range pubkeys {
		xonly := schnorr.SerializePubKey(pubkey)
		if bytes.Equal(xonly, expectedPublicKeyXonly) {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("tweaked arkade script public key not found in tapscript")
	}

	return &ArkadeScript{
		script:  entry.Script,
		hash:    scriptHash,
		witness: entry.Witness,
		pubkey:  expectedPublicKey,
		tapLeaf: txscript.NewBaseTapLeaf(spendingTapscript.Script),
	}, nil
}

func (s *ArkadeScript) Execute(spendingTx *wire.MsgTx, prevoutFetcher txscript.PrevOutputFetcher, inputIndex int, opts ...ExecuteOption) error {
	prevOut := prevoutFetcher.FetchPrevOutput(spendingTx.TxIn[inputIndex].PreviousOutPoint)
	inputAmount := int64(0)
	if prevOut != nil {
		inputAmount = prevOut.Value
	}

	engine, err := NewEngine(
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

	for _, opt := range opts {
		opt(engine)
	}

	ext, err := extension.NewExtensionFromTx(spendingTx)
	if err == nil {
		if ap := ext.GetAssetPacket(); ap != nil {
			engine.SetAssetPacket(ap)
		}
	}

	if len(s.witness) > 0 {
		engine.SetStack(s.witness)
	}

	if err := engine.Execute(); err != nil {
		return fmt.Errorf("failed to execute arkade script: %w", err)
	}

	return nil
}

func (s *ArkadeScript) Hash() []byte {
	return append([]byte(nil), s.hash...)
}

func (s *ArkadeScript) PubKey() *btcec.PublicKey {
	return s.pubkey
}

func (s *ArkadeScript) TapLeaf() txscript.TapLeaf {
	return s.tapLeaf
}

func (s *ArkadeScript) Script() []byte {
	return append([]byte(nil), s.script...)
}
