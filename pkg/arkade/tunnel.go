package arkade

import (
	"bytes"

	"github.com/btcsuite/btcd/txscript"
)

const (
	TunnelScriptPubKey = 1 << iota
	TunnelValue
)

const tunnelFlags = TunnelScriptPubKey | TunnelValue

func opcodeTunnel(op *opcode, data []byte, vm *Engine) error {
	exceptionCount, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if exceptionCount != 0 {
		return tunnelError("asset exceptions require asset tunneling")
	}

	flags, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if flags <= 0 || flags&^scriptNum(tunnelFlags) != 0 {
		return tunnelError("invalid tunnel flags")
	}

	outputIndex, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if outputIndex < 0 || int64(outputIndex) >= int64(len(vm.tx.TxOut)) {
		return tunnelError("output index out of range")
	}
	if vm.txIdx < 0 || vm.txIdx >= len(vm.tx.TxIn) {
		return tunnelError("input index out of range")
	}
	if vm.prevOutFetcher == nil {
		return tunnelError("missing prevout fetcher")
	}

	outpoint := vm.tx.TxIn[vm.txIdx].PreviousOutPoint
	output := vm.tx.TxOut[int(outputIndex)]
	if flags&TunnelScriptPubKey != 0 {
		script := vm.prevOutFetcher.FetchVtxoPrevOutPkScript(outpoint)
		if script == nil {
			return tunnelError("source script is missing")
		}
		if !bytes.Equal(script, output.PkScript) {
			return tunnelError("selected output does not preserve source script")
		}
	}
	if flags&TunnelValue != 0 {
		prevout := vm.prevOutFetcher.FetchPrevOutput(outpoint)
		if prevout == nil {
			return tunnelError("source prevout is missing")
		}
		if prevout.Value != output.Value {
			return tunnelError("selected output does not preserve source value")
		}
	}

	vm.dstack.PushBool(true)
	return nil
}

func tunnelError(description string) error {
	return scriptError(txscript.ErrInvalidStackOperation, description)
}
