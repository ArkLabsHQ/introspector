package arkade

import (
	"fmt"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestAssetOpcodes(t *testing.T) {
	t.Parallel()

	// A known txid used for asset IDs in tests.
	assetTxid := chainhash.Hash{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	// A second txid used for intent inputs.
	intentTxid := chainhash.Hash{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}

	// Control asset txid.
	ctrlTxid := chainhash.Hash{
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	// Packet with two groups:
	// Group 0: existing asset (has AssetId), with control asset by ID, 2 local inputs, 1 output
	// Group 1: fresh issuance (nil AssetId), no control asset, no inputs, 1 output
	twoGroupPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 3},
			ControlAsset: &asset.AssetRef{
				Type:    asset.AssetRefByID,
				AssetId: asset.AssetId{Txid: ctrlTxid, Index: 7},
			},
			Inputs: []asset.AssetInput{
				{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 500},
				{Type: asset.AssetInputTypeIntent, Vin: 1, Txid: intentTxid, Amount: 300},
			},
			Outputs: []asset.AssetOutput{
				{Vout: 0, Amount: 800},
			},
			Metadata: nil,
		},
		{
			AssetId:      nil, // fresh issuance
			ControlAsset: nil,
			Inputs:       nil,
			Outputs: []asset.AssetOutput{
				{Vout: 0, Amount: 1000},
				{Vout: 1, Amount: 2000},
			},
			Metadata: nil,
		},
	}

	// Packet with control asset by group index.
	ctrlByGroupPacket := asset.Packet{
		{
			AssetId: &asset.AssetId{Txid: assetTxid, Index: 0},
			Inputs:  nil,
			Outputs: []asset.AssetOutput{{Vout: 0, Amount: 100}},
		},
		{
			AssetId: nil, // fresh issuance
			ControlAsset: &asset.AssetRef{
				Type:       asset.AssetRefByGroup,
				GroupIndex: 0,
			},
			Inputs:  nil,
			Outputs: []asset.AssetOutput{{Vout: 1, Amount: 200}},
		},
	}

	// Packet with metadata.
	md1, _ := asset.NewMetadata("name", "TestToken")
	md2, _ := asset.NewMetadata("symbol", "TT")
	metadataPacket := asset.Packet{
		{
			AssetId:  &asset.AssetId{Txid: assetTxid, Index: 0},
			Inputs:   nil,
			Outputs:  []asset.AssetOutput{{Vout: 0, Amount: 100}},
			Metadata: []asset.Metadata{*md1, *md2},
		},
	}

	// Compute expected metadata hash.
	expectedMetadataHash, _ := computeMetadataMerkleRoot(metadataPacket[0].Metadata)

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {
			Value: 1000000000,
			PkScript: []byte{
				OP_1, OP_DATA_32,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
	})

	simpleTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
		},
		TxOut: []*wire.TxOut{
			{Value: 500, PkScript: nil},
			{Value: 300, PkScript: nil},
		},
	}

	type testCase struct {
		valid       bool
		assetPacket asset.Packet
	}

	type fixture struct {
		name   string
		script *txscript.ScriptBuilder
		cases  []testCase
	}

	tests := []fixture{
		// ========== OP_INSPECTNUMASSETGROUPS ==========
		{
			name: "OP_INSPECTNUMASSETGROUPS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMASSETGROUPS).
				AddInt64(2).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTNUMASSETGROUPS_no_packet",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMASSETGROUPS),
			cases: []testCase{
				{valid: false, assetPacket: nil},
			},
		},

		// ========== OP_INSPECTASSETGROUPASSETID ==========
		{
			name: "OP_INSPECTASSETGROUPASSETID_existing",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddOp(OP_INSPECTASSETGROUPASSETID).
				AddInt64(3). // expected gidx
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // expected txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPASSETID_fresh_issuance",
			// For fresh issuance (nil AssetId), the opcode pushes the current tx hash and the group index.
			// We verify the group index == 1 using EQUALVERIFY, then drop the txid with TRUE.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group index (fresh issuance)
				AddOp(OP_INSPECTASSETGROUPASSETID).
				AddInt64(1). // expected group index as gidx
				AddOp(OP_EQUALVERIFY).
				// txid is the tx hash - just check it's 32 bytes via SIZE
				AddOp(OP_SIZE).
				AddInt64(32).
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_DROP). // drop the txid
				AddOp(OP_TRUE),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPASSETID_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(5). // out of range
				AddOp(OP_INSPECTASSETGROUPASSETID),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPCTRL ==========
		{
			name: "OP_INSPECTASSETGROUPCTRL_by_id",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group 0 has control asset by ID
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddInt64(7). // expected ctrl gidx
				AddOp(OP_EQUALVERIFY).
				AddData(ctrlTxid[:]). // expected ctrl txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPCTRL_none",
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group 1 has no control asset
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddInt64(-1). // expected -1
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPCTRL_by_group_index",
			// Group 1 has control asset referencing group 0 (which has AssetId).
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group 1
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddInt64(0). // expected ctrl gidx (group 0's AssetId.Index)
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // expected ctrl txid (group 0's AssetId.Txid)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: ctrlByGroupPacket},
			},
		},

		// ========== OP_FINDASSETGROUPBYASSETID ==========
		{
			name: "OP_FINDASSETGROUPBYASSETID_found",
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]). // txid to search
				AddInt64(3).           // gidx to search
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddInt64(0). // expected group index
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_FINDASSETGROUPBYASSETID_not_found",
			script: txscript.NewScriptBuilder().
				AddData(assetTxid[:]). // txid to search
				AddInt64(99).          // wrong gidx
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddInt64(-1). // not found
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPMETADATAHASH ==========
		{
			name: "OP_INSPECTASSETGROUPMETADATAHASH",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddOp(OP_INSPECTASSETGROUPMETADATAHASH).
				AddData(expectedMetadataHash[:]). // expected hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: metadataPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPMETADATAHASH_empty",
			// Empty metadata should produce zero hash.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddOp(OP_INSPECTASSETGROUPMETADATAHASH).
				AddData(make([]byte, 32)). // zero hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPNUM ==========
		{
			name: "OP_INSPECTASSETGROUPNUM_inputs",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // source=0 (inputs)
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddInt64(2). // 2 inputs in group 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPNUM_outputs",
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group index
				AddInt64(1). // source=1 (outputs)
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddInt64(2). // 2 outputs in group 1
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPNUM_both",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(2). // source=2 (both)
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddInt64(1). // output count
				AddOp(OP_EQUALVERIFY).
				AddInt64(2). // input count
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPNUM_invalid_source",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(3). // invalid source
				AddOp(OP_INSPECTASSETGROUPNUM),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUP (input details) ==========
		{
			name: "OP_INSPECTASSETGROUP_local_input",
			// Group 0, input 0 is local: type=1, vin=0, amount=500
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(0). // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(500). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // vin
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // type (local)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_intent_input",
			// Group 0, input 1 is intent: type=2, txid, vin=1, amount=300
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(1). // item index
				AddInt64(0). // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(300). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // vin
				AddOp(OP_EQUALVERIFY).
				AddData(intentTxid[:]). // txid (only for intent inputs)
				AddOp(OP_EQUALVERIFY).
				AddInt64(2). // type (intent)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_output",
			// Group 0, output 0: type=1, vout=0, amount=800
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(1). // source=1 (output)
				AddOp(OP_INSPECTASSETGROUP).
				AddInt64(800). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // vout
				AddOp(OP_EQUALVERIFY).
				AddInt64(1). // type (always 1 for outputs)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_input_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(0).  // group index
				AddInt64(10). // out of range item index
				AddInt64(0).  // source=0 (input)
				AddOp(OP_INSPECTASSETGROUP),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUP_invalid_source",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // item index
				AddInt64(5). // invalid source
				AddOp(OP_INSPECTASSETGROUP),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTASSETGROUPSUM ==========
		{
			name: "OP_INSPECTASSETGROUPSUM_inputs",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(0). // source=0 (inputs)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(800). // 500 + 300
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_outputs",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(1). // source=1 (outputs)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(800). // single output of 800
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_both",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(2). // source=2 (both)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(800). // output sum
				AddOp(OP_EQUALVERIFY).
				AddInt64(800). // input sum
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_outputs_group1",
			script: txscript.NewScriptBuilder().
				AddInt64(1). // group 1
				AddInt64(1). // source=1 (outputs)
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddInt64(3000). // 1000 + 2000
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTASSETGROUPSUM_invalid_source",
			script: txscript.NewScriptBuilder().
				AddInt64(0). // group index
				AddInt64(3). // invalid source
				AddOp(OP_INSPECTASSETGROUPSUM),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTOUTASSETCOUNT ==========
		{
			name: "OP_INSPECTOUTASSETCOUNT_output0",
			// Output 0 has assets from both group 0 (800) and group 1 (1000) => 2 entries.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddInt64(2).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETCOUNT_output1",
			// Output 1 has assets from group 1 only (2000) => 1 entry.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // output index
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddInt64(1).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETCOUNT_no_assets",
			// Output 99 has no asset entries.
			script: txscript.NewScriptBuilder().
				AddInt64(99). // output index with no assets
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTOUTASSETAT ==========
		{
			name: "OP_INSPECTOUTASSETAT_output0_first",
			// Output 0, asset 0: from group 0 (existing asset).
			script: txscript.NewScriptBuilder().
				AddInt64(0). // output index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTOUTASSETAT).
				AddInt64(800). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // gidx (group index in packet)
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // txid
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETAT_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(0).  // output index
				AddInt64(99). // out of range asset index
				AddOp(OP_INSPECTOUTASSETAT),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTOUTASSETLOOKUP ==========
		{
			name: "OP_INSPECTOUTASSETLOOKUP_found",
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // output index
				AddData(assetTxid[:]). // txid
				AddInt64(0).           // gidx (group index in packet)
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddInt64(800). // expected amount
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTOUTASSETLOOKUP_not_found",
			script: txscript.NewScriptBuilder().
				AddInt64(1).           // output 1
				AddData(assetTxid[:]). // txid
				AddInt64(0).           // gidx 0
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddInt64(-1). // not found
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTINASSETCOUNT ==========
		{
			name: "OP_INSPECTINASSETCOUNT_input0",
			// Input 0 has 1 asset entry (group 0, local input at vin=0).
			script: txscript.NewScriptBuilder().
				AddInt64(0). // input index
				AddOp(OP_INSPECTINASSETCOUNT).
				AddInt64(1).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETCOUNT_input1",
			// Input 1 has 1 asset entry (group 0, intent input at vin=1).
			script: txscript.NewScriptBuilder().
				AddInt64(1). // input index
				AddOp(OP_INSPECTINASSETCOUNT).
				AddInt64(1).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETCOUNT_no_assets",
			script: txscript.NewScriptBuilder().
				AddInt64(99). // input with no assets
				AddOp(OP_INSPECTINASSETCOUNT).
				AddInt64(0).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTINASSETAT ==========
		{
			name: "OP_INSPECTINASSETAT_local",
			// Input 0, asset 0: local input from group 0.
			// For local inputs, txid = group's asset txid.
			script: txscript.NewScriptBuilder().
				AddInt64(0). // input index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTINASSETAT).
				AddInt64(500). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // gidx (group index)
				AddOp(OP_EQUALVERIFY).
				AddData(assetTxid[:]). // txid (group's asset txid for local)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETAT_intent",
			// Input 1, asset 0: intent input from group 0.
			// For intent inputs, txid = intent txid.
			script: txscript.NewScriptBuilder().
				AddInt64(1). // input index
				AddInt64(0). // asset index
				AddOp(OP_INSPECTINASSETAT).
				AddInt64(300). // amount
				AddOp(OP_EQUALVERIFY).
				AddInt64(0). // gidx (group index)
				AddOp(OP_EQUALVERIFY).
				AddData(intentTxid[:]). // txid (intent txid)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETAT_out_of_range",
			script: txscript.NewScriptBuilder().
				AddInt64(0).  // input index
				AddInt64(99). // out of range asset index
				AddOp(OP_INSPECTINASSETAT),
			cases: []testCase{
				{valid: false, assetPacket: twoGroupPacket},
			},
		},

		// ========== OP_INSPECTINASSETLOOKUP ==========
		{
			name: "OP_INSPECTINASSETLOOKUP_local_found",
			// Lookup local input: input 0, group 0 asset txid => 500.
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // input index
				AddData(assetTxid[:]). // txid (group's asset txid for local)
				AddInt64(0).           // gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddInt64(500).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETLOOKUP_intent_found",
			// Lookup intent input: input 1, intent txid => 300.
			script: txscript.NewScriptBuilder().
				AddInt64(1).            // input index
				AddData(intentTxid[:]). // txid (intent txid)
				AddInt64(0).            // gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddInt64(300).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
		{
			name: "OP_INSPECTINASSETLOOKUP_not_found",
			script: txscript.NewScriptBuilder().
				AddInt64(0).           // input index
				AddData(assetTxid[:]). // txid
				AddInt64(5).           // wrong gidx
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddInt64(-1). // not found
				AddOp(OP_EQUAL),
			cases: []testCase{
				{valid: true, assetPacket: twoGroupPacket},
			},
		},
	}

	for _, test := range tests {
		for caseIndex, c := range test.cases {
			t.Run(fmt.Sprintf("%s_%d", test.name, caseIndex), func(tt *testing.T) {
				script, err := test.script.Script()
				if err != nil {
					tt.Fatalf("Script build failed: %v", err)
				}

				engine, err := NewEngine(
					script,
					simpleTx, 0,
					txscript.StandardVerifyFlags&txscript.ScriptVerifyTaproot,
					txscript.NewSigCache(100),
					txscript.NewTxSigHashes(simpleTx, prevoutFetcher),
					0,
					prevoutFetcher,
				)
				if err != nil {
					tt.Fatalf("NewEngine failed: %v", err)
				}

				if c.assetPacket != nil {
					engine.SetAssetPacket(c.assetPacket)
				}

				err = engine.Execute()
				if c.valid && err != nil {
					tt.Errorf("Execute failed: %v", err)
				}
				if !c.valid && err == nil {
					tt.Errorf("Execute should have failed")
				}
			})
		}
	}
}
