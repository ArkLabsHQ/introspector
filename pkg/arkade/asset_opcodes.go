package arkade

import (
	"crypto/sha256"
	"math/big"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

// opcodeInspectNumAssetGroups pushes the total number of asset groups in the packet onto the stack.
func opcodeInspectNumAssetGroups(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}
	vm.dstack.PushInt(scriptNum(len(vm.assetPacket)))
	return nil
}

// opcodeInspectAssetGroupAssetId pops a group index k and pushes the asset ID (txid, index) for that group.
// If the group has no AssetId, pushes the current transaction hash and k.
func opcodeInspectAssetGroupAssetId(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	if group.AssetId == nil {
		txHash := vm.tx.TxHash()
		vm.dstack.PushByteArray(txHash[:])
		vm.dstack.PushInt(scriptNum(k))
		return nil
	}

	vm.dstack.PushByteArray(group.AssetId.Txid[:])
	vm.dstack.PushInt(scriptNum(group.AssetId.Index))
	return nil
}

// opcodeInspectAssetGroupCtrl pops a group index k and pushes the control asset reference (txid, index).
// Pushes -1 if there is no control asset.
func opcodeInspectAssetGroupCtrl(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	if group.ControlAsset == nil {
		vm.dstack.PushInt(-1)
		return nil
	}

	if group.ControlAsset.Type == asset.AssetRefByID {
		vm.dstack.PushByteArray(group.ControlAsset.AssetId.Txid[:])
		vm.dstack.PushInt(scriptNum(group.ControlAsset.AssetId.Index))
		return nil
	}

	if group.ControlAsset.Type == asset.AssetRefByGroup {
		if group.ControlAsset.GroupIndex >= uint16(len(vm.assetPacket)) {
			return scriptError(txscript.ErrInvalidStackOperation, "control asset group index out of range")
		}
		ctrlGroup := vm.assetPacket[group.ControlAsset.GroupIndex]
		if ctrlGroup.AssetId == nil {
			// Referenced group is a fresh issuance, use current tx hash and the group index
			txHash := vm.tx.TxHash()
			vm.dstack.PushByteArray(txHash[:])
			vm.dstack.PushInt(scriptNum(group.ControlAsset.GroupIndex))
		} else {
			vm.dstack.PushByteArray(ctrlGroup.AssetId.Txid[:])
			vm.dstack.PushInt(scriptNum(ctrlGroup.AssetId.Index))
		}
		return nil
	}

	return scriptError(txscript.ErrInvalidStackOperation, "invalid control asset type")
}

// opcodeFindAssetGroupByAssetId pops an asset ID (gidx, txid) and searches for the matching group index.
// Pushes the group index if found, or -1 if not found.
func opcodeFindAssetGroupByAssetId(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	gidx, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	txidBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	if len(txidBytes) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid txid length")
	}

	var searchTxid chainhash.Hash
	copy(searchTxid[:], txidBytes)

	for i, group := range vm.assetPacket {
		if group.AssetId == nil {
			txHash := vm.tx.TxHash()
			if txHash.IsEqual(&searchTxid) && scriptNum(i) == gidx {
				vm.dstack.PushInt(scriptNum(i))
				return nil
			}
			continue
		}

		if group.AssetId.Txid.IsEqual(&searchTxid) && scriptNum(group.AssetId.Index) == gidx {
			vm.dstack.PushInt(scriptNum(i))
			return nil
		}
	}

	vm.dstack.PushInt(-1)
	return nil
}

// opcodeInspectAssetGroupMetadataHash pops a group index k and pushes the Merkle root hash of its metadata.
func opcodeInspectAssetGroupMetadataHash(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	hash, err := computeMetadataMerkleRoot(group.Metadata)
	if err != nil {
		return scriptError(txscript.ErrInvalidStackOperation, "failed to compute metadata hash: "+err.Error())
	}
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeInspectAssetGroupNum pops source and group index k, then pushes count(s) based on source:
// source=0: input count, source=1: output count, source=2: both input and output counts.
func opcodeInspectAssetGroupNum(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	switch source {
	case 0:
		vm.dstack.PushInt(scriptNum(len(group.Inputs)))
	case 1:
		vm.dstack.PushInt(scriptNum(len(group.Outputs)))
	case 2:
		vm.dstack.PushInt(scriptNum(len(group.Inputs)))
		vm.dstack.PushInt(scriptNum(len(group.Outputs)))
	default:
		return scriptError(txscript.ErrInvalidStackOperation, "invalid source value")
	}
	return nil
}

// opcodeInspectAssetGroup pops source, item index j, and group index k, then pushes details of the item.
// source=0: input details (type, [txid if intent], vin, amount), source=1: output details (1, vout, amount).
func opcodeInspectAssetGroup(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	j, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	switch source {
	case 0:
		if int(j) >= len(group.Inputs) || j < 0 {
			return scriptError(txscript.ErrInvalidStackOperation, "input index out of range")
		}
		input := group.Inputs[int(j)]

		vm.dstack.PushInt(scriptNum(input.Type))
		if input.Type == asset.AssetInputTypeIntent {
			vm.dstack.PushByteArray(input.Txid[:])
		}
		vm.dstack.PushInt(scriptNum(input.Vin))
		vm.dstack.PushInt(scriptNum(input.Amount))

	case 1:
		if int(j) >= len(group.Outputs) || j < 0 {
			return scriptError(txscript.ErrInvalidStackOperation, "output index out of range")
		}
		output := group.Outputs[int(j)]

		vm.dstack.PushInt(1)
		vm.dstack.PushInt(scriptNum(output.Vout))
		vm.dstack.PushInt(scriptNum(output.Amount))

	default:
		return scriptError(txscript.ErrInvalidStackOperation, "invalid source value")
	}
	return nil
}

// opcodeInspectAssetGroupSum pops source and group index k, then pushes sum(s) based on source:
// source=0: input sum, source=1: output sum, source=2: both input and output sums.
func opcodeInspectAssetGroupSum(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if int(k) >= len(vm.assetPacket) || k < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "group index out of range")
	}

	group := vm.assetPacket[int(k)]

	switch source {
	case 0:
		sum := safeSumInputs(group.Inputs)
		if !sum.IsUint64() {
			return scriptError(txscript.ErrInvalidStackOperation, "amount overflow")
		}
		vm.dstack.PushInt(scriptNum(sum.Uint64()))
	case 1:
		sum := safeSumOutputs(group.Outputs)
		if !sum.IsUint64() {
			return scriptError(txscript.ErrInvalidStackOperation, "amount overflow")
		}
		vm.dstack.PushInt(scriptNum(sum.Uint64()))
	case 2:
		inSum := safeSumInputs(group.Inputs)
		if !inSum.IsUint64() {
			return scriptError(txscript.ErrInvalidStackOperation, "amount overflow")
		}
		vm.dstack.PushInt(scriptNum(inSum.Uint64()))
		outSum := safeSumOutputs(group.Outputs)
		if !outSum.IsUint64() {
			return scriptError(txscript.ErrInvalidStackOperation, "amount overflow")
		}
		vm.dstack.PushInt(scriptNum(outSum.Uint64()))
	default:
		return scriptError(txscript.ErrInvalidStackOperation, "invalid source value")
	}
	return nil
}

// opcodeInspectOutAssetCount pops an output index o and pushes the number of asset entries at that output.
func opcodeInspectOutAssetCount(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	count := 0
	for _, group := range vm.assetPacket {
		for _, output := range group.Outputs {
			if uint32(output.Vout) == uint32(o) {
				count++
			}
		}
	}

	vm.dstack.PushInt(scriptNum(count))
	return nil
}

// opcodeInspectOutAssetAt pops asset index t and output index o, then pushes the asset entry (txid, gidx, amount).
func opcodeInspectOutAssetAt(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	t, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if t < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
	}

	txHash := vm.tx.TxHash()
	idx := 0

	for gidx, group := range vm.assetPacket {
		var assetTxid chainhash.Hash
		if group.AssetId == nil {
			assetTxid = txHash
		} else {
			assetTxid = group.AssetId.Txid
		}

		for _, output := range group.Outputs {
			if uint32(output.Vout) == uint32(o) {
				if scriptNum(idx) == t {
					vm.dstack.PushByteArray(assetTxid[:])
					vm.dstack.PushInt(scriptNum(gidx))
					vm.dstack.PushInt(scriptNum(output.Amount))
					return nil
				}
				idx++
			}
		}
	}

	return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
}

// opcodeInspectOutAssetLookup pops gidx, txid, and output index o, then looks up the asset amount.
// Pushes the amount if found, or -1 if not found.
func opcodeInspectOutAssetLookup(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	gidx, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	txidBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if len(txidBytes) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid txid length")
	}

	var searchTxid chainhash.Hash
	copy(searchTxid[:], txidBytes)

	txHash := vm.tx.TxHash()

	for groupIdx, group := range vm.assetPacket {
		if scriptNum(groupIdx) != gidx {
			continue
		}

		var assetTxid chainhash.Hash
		if group.AssetId == nil {
			assetTxid = txHash
		} else {
			assetTxid = group.AssetId.Txid
		}

		if !assetTxid.IsEqual(&searchTxid) {
			continue
		}

		for _, output := range group.Outputs {
			if uint32(output.Vout) == uint32(o) {
				vm.dstack.PushInt(scriptNum(output.Amount))
				return nil
			}
		}
	}

	vm.dstack.PushInt(-1)
	return nil
}

// opcodeInspectInAssetCount pops an input index i and pushes the number of asset entries at that input.
func opcodeInspectInAssetCount(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	count := 0
	for _, group := range vm.assetPacket {
		for _, input := range group.Inputs {
			if uint32(input.Vin) == uint32(i) {
				count++
			}
		}
	}

	vm.dstack.PushInt(scriptNum(count))
	return nil
}

// opcodeInspectInAssetAt pops asset index t and input index i, then pushes the asset entry (txid, gidx, amount).
func opcodeInspectInAssetAt(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	t, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if t < 0 {
		return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
	}

	txHash := vm.tx.TxHash()
	idx := 0

	for gidx, group := range vm.assetPacket {
		var assetTxid chainhash.Hash
		if group.AssetId == nil {
			assetTxid = txHash
		} else {
			assetTxid = group.AssetId.Txid
		}

		for _, input := range group.Inputs {
			if uint32(input.Vin) == uint32(i) {
				if scriptNum(idx) == t {
					var inputTxid chainhash.Hash
					if input.Type == asset.AssetInputTypeIntent {
						inputTxid = input.Txid
					} else {
						inputTxid = assetTxid
					}

					vm.dstack.PushByteArray(inputTxid[:])
					vm.dstack.PushInt(scriptNum(gidx))
					vm.dstack.PushInt(scriptNum(input.Amount))
					return nil
				}
				idx++
			}
		}
	}

	return scriptError(txscript.ErrInvalidStackOperation, "asset index out of range")
}

// opcodeInspectInAssetLookup pops gidx, txid, and input index i, then looks up the asset amount.
// Pushes the amount if found, or -1 if not found.
func opcodeInspectInAssetLookup(op *opcode, data []byte, vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidStackOperation, "no asset packet")
	}

	gidx, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	txidBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if len(txidBytes) != 32 {
		return scriptError(txscript.ErrInvalidStackOperation, "invalid txid length")
	}

	var searchTxid chainhash.Hash
	copy(searchTxid[:], txidBytes)

	txHash := vm.tx.TxHash()

	for groupIdx, group := range vm.assetPacket {
		if scriptNum(groupIdx) != gidx {
			continue
		}

		var assetTxid chainhash.Hash
		if group.AssetId == nil {
			assetTxid = txHash
		} else {
			assetTxid = group.AssetId.Txid
		}

		for _, input := range group.Inputs {
			if uint32(input.Vin) != uint32(i) {
				continue
			}

			var inputTxid chainhash.Hash
			if input.Type == asset.AssetInputTypeIntent {
				inputTxid = input.Txid
			} else {
				inputTxid = assetTxid
			}

			if inputTxid.IsEqual(&searchTxid) {
				vm.dstack.PushInt(scriptNum(input.Amount))
				return nil
			}
		}
	}

	vm.dstack.PushInt(-1)
	return nil
}

// computeMetadataMerkleRoot computes the Merkle root hash of the given metadata slice.
func computeMetadataMerkleRoot(metadata []asset.Metadata) (chainhash.Hash, error) {
	if len(metadata) == 0 {
		return chainhash.Hash{}, nil
	}

	hashes := make([]chainhash.Hash, len(metadata))
	for i, md := range metadata {
		serialized, err := md.Serialize()
		if err != nil {
			return chainhash.Hash{}, err
		}
		hashes[i] = sha256.Sum256(serialized)
	}

	for len(hashes) > 1 {
		var nextLevel []chainhash.Hash
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				var combined [64]byte
				copy(combined[:32], hashes[i][:])
				copy(combined[32:], hashes[i+1][:])
				hash := sha256.Sum256(combined[:])
				nextLevel = append(nextLevel, hash)
			} else {
				nextLevel = append(nextLevel, hashes[i])
			}
		}
		hashes = nextLevel
	}

	return hashes[0], nil
}

// safeSumInputs computes the total amount across all inputs using big.Int to avoid overflow.
func safeSumInputs(inputs []asset.AssetInput) *big.Int {
	sum := new(big.Int)
	for _, input := range inputs {
		sum.Add(sum, new(big.Int).SetUint64(input.Amount))
	}
	return sum
}

// safeSumOutputs computes the total amount across all outputs using big.Int to avoid overflow.
func safeSumOutputs(outputs []asset.AssetOutput) *big.Int {
	sum := new(big.Int)
	for _, output := range outputs {
		sum.Add(sum, new(big.Int).SetUint64(output.Amount))
	}
	return sum
}
