package arkade

import (
	"encoding/binary"

	"github.com/btcsuite/btcd/txscript"
)

// checkAssetPacket verifies that the asset packet is set on the engine
func checkAssetPacket(vm *Engine) error {
	if vm.assetPacket == nil {
		return scriptError(txscript.ErrInvalidIndex, "asset packet not set")
	}
	return nil
}

// checkGroupIndex validates the group index k is within range
func checkGroupIndex(vm *Engine, k int) error {
	if k < 0 || k >= len(vm.assetPacket.Groups) {
		return scriptError(txscript.ErrInvalidIndex, "asset group index out of range")
	}
	return nil
}

// pushAssetID pushes an AssetID (txid32, gidx_u16) onto the stack
func pushAssetID(vm *Engine, id AssetID) {
	txid := make([]byte, 32)
	copy(txid, id.Txid[:])
	vm.dstack.PushByteArray(txid)
	vm.dstack.PushInt(scriptNum(id.Gidx))
}

// pushLE64 pushes a uint64 as 8 bytes little-endian
func pushLE64(vm *Engine, v uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	vm.dstack.PushByteArray(buf)
}

// popAssetID pops an AssetID (gidx_u16 then txid32) from the stack
func popAssetID(vm *Engine) (AssetID, error) {
	gidx, err := vm.dstack.PopInt()
	if err != nil {
		return AssetID{}, err
	}
	txidBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return AssetID{}, err
	}
	if len(txidBytes) != 32 {
		return AssetID{}, scriptError(txscript.ErrInvalidStackOperation, "asset ID txid must be 32 bytes")
	}
	var id AssetID
	copy(id.Txid[:], txidBytes)
	id.Gidx = uint16(gidx)
	return id, nil
}

// OP_INSPECTNUMASSETGROUPS: → K (number of groups)
func opcodeInspectNumAssetGroups(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	vm.dstack.PushInt(scriptNum(len(vm.assetPacket.Groups)))
	return nil
}

// OP_INSPECTASSETGROUPASSETID: k → txid32 gidx_u16
func opcodeInspectAssetGroupAssetID(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	pushAssetID(vm, vm.assetPacket.Groups[k].AssetID)
	return nil
}

// OP_INSPECTASSETGROUPCTRL: k → txid32 gidx_u16 | -1
func opcodeInspectAssetGroupCtrl(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	ctrl := vm.assetPacket.Groups[k].Control
	if ctrl == nil {
		vm.dstack.PushInt(-1)
	} else {
		pushAssetID(vm, *ctrl)
	}
	return nil
}

// OP_FINDASSETGROUPBYASSETID: txid32 gidx_u16 → k | -1
func opcodeFindAssetGroupByAssetID(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	id, err := popAssetID(vm)
	if err != nil {
		return err
	}
	for i, g := range vm.assetPacket.Groups {
		if g.AssetID.Txid == id.Txid && g.AssetID.Gidx == id.Gidx {
			vm.dstack.PushInt(scriptNum(i))
			return nil
		}
	}
	vm.dstack.PushInt(-1)
	return nil
}

// OP_INSPECTASSETGROUPMETADATAHASH: k → hash32
func opcodeInspectAssetGroupMetadataHash(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	hash := make([]byte, 32)
	copy(hash, vm.assetPacket.Groups[k].MetadataHash[:])
	vm.dstack.PushByteArray(hash)
	return nil
}

// OP_INSPECTASSETGROUPNUM: k source_u8 → count or in_count out_count
// source: 0=inputs, 1=outputs, 2=both
func opcodeInspectAssetGroupNum(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	group := vm.assetPacket.Groups[k]
	switch source {
	case 0:
		vm.dstack.PushInt(scriptNum(len(group.Inputs)))
	case 1:
		vm.dstack.PushInt(scriptNum(len(group.Outputs)))
	case 2:
		vm.dstack.PushInt(scriptNum(len(group.Inputs)))
		vm.dstack.PushInt(scriptNum(len(group.Outputs)))
	default:
		return scriptError(txscript.ErrInvalidIndex, "invalid source for OP_INSPECTASSETGROUPNUM")
	}
	return nil
}

// OP_INSPECTASSETGROUP: k j source_u8 → type_u8 data... amount_u64
// source: 0=input, 1=output
func opcodeInspectAssetGroup(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
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
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	group := vm.assetPacket.Groups[k]
	switch source {
	case 0: // input
		if int(j) < 0 || int(j) >= len(group.Inputs) {
			return scriptError(txscript.ErrInvalidIndex, "asset group input index out of range")
		}
		inp := group.Inputs[j]
		vm.dstack.PushInt(scriptNum(inp.Type))
		if inp.Type == AssetInputTypeLocal {
			vm.dstack.PushInt(scriptNum(inp.InputIndex))
		} else {
			txid := make([]byte, 32)
			copy(txid, inp.Txid[:])
			vm.dstack.PushByteArray(txid)
			vm.dstack.PushInt(scriptNum(inp.OutputIndex))
		}
		pushLE64(vm, inp.Amount)
	case 1: // output
		if int(j) < 0 || int(j) >= len(group.Outputs) {
			return scriptError(txscript.ErrInvalidIndex, "asset group output index out of range")
		}
		out := group.Outputs[j]
		vm.dstack.PushInt(scriptNum(out.Type))
		vm.dstack.PushInt(scriptNum(out.OutputIndex))
		pushLE64(vm, out.Amount)
	default:
		return scriptError(txscript.ErrInvalidIndex, "invalid source for OP_INSPECTASSETGROUP")
	}
	return nil
}

// OP_INSPECTASSETGROUPSUM: k source_u8 → sum or in_sum out_sum
// source: 0=inputs, 1=outputs, 2=both
func opcodeInspectAssetGroupSum(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	source, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	group := vm.assetPacket.Groups[k]
	var inSum, outSum uint64
	for _, inp := range group.Inputs {
		inSum += inp.Amount
	}
	for _, out := range group.Outputs {
		outSum += out.Amount
	}
	switch source {
	case 0:
		pushLE64(vm, inSum)
	case 1:
		pushLE64(vm, outSum)
	case 2:
		pushLE64(vm, inSum)
		pushLE64(vm, outSum)
	default:
		return scriptError(txscript.ErrInvalidIndex, "invalid source for OP_INSPECTASSETGROUPSUM")
	}
	return nil
}

// OP_INSPECTOUTASSETCOUNT: o → n
func opcodeInspectOutAssetCount(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	entries := vm.assetPacket.OutputAssets[uint32(o)]
	vm.dstack.PushInt(scriptNum(len(entries)))
	return nil
}

// OP_INSPECTOUTASSETAT: o t → txid32 gidx_u16 amount_u64
func opcodeInspectOutAssetAt(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	t, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	entries := vm.assetPacket.OutputAssets[uint32(o)]
	if int(t) < 0 || int(t) >= len(entries) {
		return scriptError(txscript.ErrInvalidIndex, "output asset index out of range")
	}
	entry := entries[t]
	pushAssetID(vm, entry.AssetID)
	pushLE64(vm, entry.Amount)
	return nil
}

// OP_INSPECTOUTASSETLOOKUP: o txid32 gidx_u16 → amount_u64 | -1
func opcodeInspectOutAssetLookup(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	id, err := popAssetID(vm)
	if err != nil {
		return err
	}
	o, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	entries := vm.assetPacket.OutputAssets[uint32(o)]
	for _, entry := range entries {
		if entry.AssetID.Txid == id.Txid && entry.AssetID.Gidx == id.Gidx {
			pushLE64(vm, entry.Amount)
			return nil
		}
	}
	vm.dstack.PushInt(-1)
	return nil
}

// OP_INSPECTINASSETCOUNT: i → n
func opcodeInspectInAssetCount(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	entries := vm.assetPacket.InputAssets[uint32(i)]
	vm.dstack.PushInt(scriptNum(len(entries)))
	return nil
}

// OP_INSPECTINASSETAT: i t → txid32 gidx_u16 amount_u64
func opcodeInspectInAssetAt(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	t, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	entries := vm.assetPacket.InputAssets[uint32(i)]
	if int(t) < 0 || int(t) >= len(entries) {
		return scriptError(txscript.ErrInvalidIndex, "input asset index out of range")
	}
	entry := entries[t]
	pushAssetID(vm, entry.AssetID)
	pushLE64(vm, entry.Amount)
	return nil
}

// OP_INSPECTINASSETLOOKUP: i txid32 gidx_u16 → amount_u64 | -1
func opcodeInspectInAssetLookup(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	id, err := popAssetID(vm)
	if err != nil {
		return err
	}
	i, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	entries := vm.assetPacket.InputAssets[uint32(i)]
	for _, entry := range entries {
		if entry.AssetID.Txid == id.Txid && entry.AssetID.Gidx == id.Gidx {
			pushLE64(vm, entry.Amount)
			return nil
		}
	}
	vm.dstack.PushInt(-1)
	return nil
}

// OP_INSPECTGROUPINTENTOUTCOUNT: k → n
func opcodeInspectGroupIntentOutCount(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	count := 0
	for _, out := range vm.assetPacket.Groups[k].Outputs {
		if out.Type == AssetOutputTypeIntent {
			count++
		}
	}
	vm.dstack.PushInt(scriptNum(count))
	return nil
}

// OP_INSPECTGROUPINTENTOUT: k j → output_index_u32 amount_u64
func opcodeInspectGroupIntentOut(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
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
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	idx := 0
	for _, out := range vm.assetPacket.Groups[k].Outputs {
		if out.Type == AssetOutputTypeIntent {
			if idx == int(j) {
				vm.dstack.PushInt(scriptNum(out.OutputIndex))
				pushLE64(vm, out.Amount)
				return nil
			}
			idx++
		}
	}
	return scriptError(txscript.ErrInvalidIndex, "intent output index out of range")
}

// OP_INSPECTGROUPINTENTINCOUNT: k → n
func opcodeInspectGroupIntentInCount(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
		return err
	}
	k, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	count := 0
	for _, inp := range vm.assetPacket.Groups[k].Inputs {
		if inp.Type == AssetInputTypeIntent {
			count++
		}
	}
	vm.dstack.PushInt(scriptNum(count))
	return nil
}

// OP_INSPECTGROUPINTENTIN: k j → txid_32 output_index_u32 amount_u64
func opcodeInspectGroupIntentIn(op *opcode, data []byte, vm *Engine) error {
	if err := checkAssetPacket(vm); err != nil {
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
	if err := checkGroupIndex(vm, int(k)); err != nil {
		return err
	}
	idx := 0
	for _, inp := range vm.assetPacket.Groups[k].Inputs {
		if inp.Type == AssetInputTypeIntent {
			if idx == int(j) {
				txid := make([]byte, 32)
				copy(txid, inp.Txid[:])
				vm.dstack.PushByteArray(txid)
				vm.dstack.PushInt(scriptNum(inp.OutputIndex))
				pushLE64(vm, inp.Amount)
				return nil
			}
			idx++
		}
	}
	return scriptError(txscript.ErrInvalidIndex, "intent input index out of range")
}
