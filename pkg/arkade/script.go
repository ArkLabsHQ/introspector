package arkade

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var ErrTweakedArkadePubKeyNotFound = errors.New("tweaked arkade script public key not found in tapscript")

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

func WithPrevoutTxs(prevoutTxs map[int]*wire.MsgTx) ExecuteOption {
	return func(engine *Engine) {
		engine.SetPrevoutTxs(prevoutTxs)
	}
}

// ReadArkadeScript reads an arkade script from an IntrospectorEntry and validates
// it against the tapscript in the PSBT input. The entry contains the script and
// witness data extracted from the Introspector Packet (OP_RETURN TLV).
func ReadArkadeScript(ptx *psbt.Packet, signerPublicKey *btcec.PublicKey, entry IntrospectorEntry) (*ArkadeScript, error) {
	inputIndex := int(entry.Vin)
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
		return nil, fmt.Errorf("failed to decode tapscript: %w", err)
	}

	var pubkeys []*btcec.PublicKey
	switch c := closure.(type) {
	case *scriptlib.MultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.CSVMultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.CLTVMultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.ConditionMultisigClosure:
		pubkeys = c.PubKeys
	case *scriptlib.ConditionCSVMultisigClosure:
		pubkeys = c.PubKeys
	default:
		return nil, fmt.Errorf("unsupported closure type: %T", closure)
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
		return nil, ErrTweakedArkadePubKeyNotFound
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

	// Parse asset packet from transaction extension if present
	ext, err := extension.NewExtensionFromTx(spendingTx)
	if err != nil {
		if !errors.Is(err, extension.ErrExtensionNotFound) {
			return fmt.Errorf("failed to parse extension: %w", err)
		}
	} else if ap := ext.GetAssetPacket(); ap != nil {
		engine.SetAssetPacket(ap)
	}

	// Parse & set introspector packet from transaction outputs if present
	packet, err := FindIntrospectorPacket(spendingTx)
	if err != nil {
		return fmt.Errorf("failed to parse introspector packet: %w", err)
	}
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
