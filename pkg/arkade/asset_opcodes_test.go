package arkade

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// testAssetTxid is a sample txid used in asset opcode tests
var testAssetTxid = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

var testControlTxid = [32]byte{
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
}

var testIntentTxid = [32]byte{
	0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
	0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}

var testMetadataHash = [32]byte{
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
}

// makeTestAssetPacket creates a standard test asset packet with two groups
func makeTestAssetPacket() *AssetPacket {
	controlID := AssetID{Txid: testControlTxid, Gidx: 1}
	return &AssetPacket{
		Groups: []AssetGroup{
			{
				AssetID:      AssetID{Txid: testAssetTxid, Gidx: 0},
				Control:      &controlID,
				MetadataHash: testMetadataHash,
				Inputs: []AssetInput{
					{Type: AssetInputTypeLocal, InputIndex: 0, Amount: 1000},
					{Type: AssetInputTypeIntent, Txid: testIntentTxid, OutputIndex: 2, Amount: 500},
				},
				Outputs: []AssetOutput{
					{Type: AssetOutputTypeLocal, OutputIndex: 0, Amount: 800},
					{Type: AssetOutputTypeIntent, OutputIndex: 1, Amount: 700},
				},
			},
			{
				AssetID:      AssetID{Txid: testControlTxid, Gidx: 1},
				Control:      nil, // no control
				MetadataHash: [32]byte{},
				Inputs: []AssetInput{
					{Type: AssetInputTypeLocal, InputIndex: 1, Amount: 200},
				},
				Outputs: []AssetOutput{
					{Type: AssetOutputTypeLocal, OutputIndex: 2, Amount: 200},
				},
			},
		},
		InputAssets: map[uint32][]InputAssetEntry{
			0: {
				{AssetID: AssetID{Txid: testAssetTxid, Gidx: 0}, Amount: 1000},
			},
			1: {
				{AssetID: AssetID{Txid: testControlTxid, Gidx: 1}, Amount: 200},
			},
		},
		OutputAssets: map[uint32][]OutputAssetEntry{
			0: {
				{AssetID: AssetID{Txid: testAssetTxid, Gidx: 0}, Amount: 800},
			},
			1: {
				{AssetID: AssetID{Txid: testAssetTxid, Gidx: 0}, Amount: 700},
			},
			2: {
				{AssetID: AssetID{Txid: testControlTxid, Gidx: 1}, Amount: 200},
			},
		},
	}
}

// makeTestTx creates a basic transaction for testing
func makeTestTx() *wire.MsgTx {
	return &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			},
		},
		TxOut: []*wire.TxOut{
			{Value: 1000000, PkScript: nil},
			{Value: 500000, PkScript: nil},
			{Value: 200000, PkScript: nil},
		},
	}
}

func encodeLE64(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}

// newAssetTestEngine creates an engine with asset packet set, running the given script
func newAssetTestEngine(t *testing.T, script []byte, packet *AssetPacket, initialStack [][]byte) *Engine {
	t.Helper()
	tx := makeTestTx()
	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {
			Value:    1000000000,
			PkScript: []byte{OP_1, OP_DATA_32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	})

	engine, err := NewEngine(
		script, tx, 0,
		txscript.StandardVerifyFlags&txscript.ScriptVerifyTaproot,
		txscript.NewSigCache(100),
		txscript.NewTxSigHashes(tx, prevoutFetcher),
		0, prevoutFetcher,
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	engine.SetAssetPacket(packet)
	if len(initialStack) > 0 {
		engine.SetStack(initialStack)
	}
	return engine
}

func TestAssetOpcodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name         string
		script       *txscript.ScriptBuilder
		packet       *AssetPacket
		stack        [][]byte
		valid        bool
		expectStack  [][]byte // optional: verify top of stack after execution
	}

	tests := []testCase{
		// OP_INSPECTNUMASSETGROUPS
		{
			name: "OP_INSPECTNUMASSETGROUPS - returns 2 groups",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMASSETGROUPS).
				AddOp(OP_2).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			valid:  true,
		},
		{
			name: "OP_INSPECTNUMASSETGROUPS - no packet fails",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMASSETGROUPS),
			packet: nil,
			valid:  false,
		},

		// OP_INSPECTASSETGROUPASSETID
		{
			name: "OP_INSPECTASSETGROUPASSETID - group 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPASSETID).
				AddOp(OP_0). // expect gidx = 0
				AddOp(OP_EQUALVERIFY).
				AddData(testAssetTxid[:]). // expect txid
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // k=0
			valid:  true,
		},
		{
			name: "OP_INSPECTASSETGROUPASSETID - out of range",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPASSETID),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x05}}, // k=5, out of range
			valid:  false,
		},

		// OP_INSPECTASSETGROUPCTRL - with control
		{
			name: "OP_INSPECTASSETGROUPCTRL - group 0 has control",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddOp(OP_1). // expect gidx = 1
				AddOp(OP_EQUALVERIFY).
				AddData(testControlTxid[:]). // expect control txid
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // k=0
			valid:  true,
		},
		// OP_INSPECTASSETGROUPCTRL - no control
		{
			name: "OP_INSPECTASSETGROUPCTRL - group 1 has no control",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPCTRL).
				AddOp(OP_1NEGATE). // expect -1
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x01}}, // k=1
			valid:  true,
		},

		// OP_FINDASSETGROUPBYASSETID - found
		{
			name: "OP_FINDASSETGROUPBYASSETID - found at index 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_0). // expect k=0
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{testAssetTxid[:], {0x00}}, // txid, gidx=0
			valid:  true,
		},
		// OP_FINDASSETGROUPBYASSETID - not found
		{
			name: "OP_FINDASSETGROUPBYASSETID - not found returns -1",
			script: txscript.NewScriptBuilder().
				AddOp(OP_FINDASSETGROUPBYASSETID).
				AddOp(OP_1NEGATE).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack: [][]byte{
				make([]byte, 32), // zero txid, not in packet
				{0x00},           // gidx=0
			},
			valid: true,
		},

		// OP_INSPECTASSETGROUPMETADATAHASH
		{
			name: "OP_INSPECTASSETGROUPMETADATAHASH - group 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPMETADATAHASH).
				AddData(testMetadataHash[:]).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // k=0
			valid:  true,
		},

		// OP_INSPECTASSETGROUPNUM - inputs
		{
			name: "OP_INSPECTASSETGROUPNUM - group 0 inputs count = 2",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddOp(OP_2).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}}, // k=0, source=0 (inputs)
			valid:  true,
		},
		// OP_INSPECTASSETGROUPNUM - outputs
		{
			name: "OP_INSPECTASSETGROUPNUM - group 0 outputs count = 2",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddOp(OP_2).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x01}}, // k=0, source=1 (outputs)
			valid:  true,
		},
		// OP_INSPECTASSETGROUPNUM - both
		{
			name: "OP_INSPECTASSETGROUPNUM - group 0 both counts",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPNUM).
				AddOp(OP_2).        // outputs = 2
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2).        // inputs = 2
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x02}}, // k=0, source=2 (both)
			valid:  true,
		},

		// OP_INSPECTASSETGROUP - LOCAL input
		{
			name: "OP_INSPECTASSETGROUP - LOCAL input type check",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUP).
				// stack: type_u8 input_index_u32 amount_u64
				AddData(encodeLE64(1000)).   // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_0).           // expected input_index = 0
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_1).           // expected type = LOCAL (1)
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}, {0x00}}, // k=0, j=0, source=0 (input)
			valid:  true,
		},
		// OP_INSPECTASSETGROUP - INTENT input
		{
			name: "OP_INSPECTASSETGROUP - INTENT input",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUP).
				// stack: type_u8 txid_32 output_index_u32 amount_u64
				AddData(encodeLE64(500)).       // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2).              // expected output_index = 2
				AddOp(OP_EQUALVERIFY).
				AddData(testIntentTxid[:]). // expected txid
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2).              // expected type = INTENT (2)
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x01}, {0x00}}, // k=0, j=1, source=0 (input)
			valid:  true,
		},
		// OP_INSPECTASSETGROUP - LOCAL output
		{
			name: "OP_INSPECTASSETGROUP - LOCAL output",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUP).
				// stack: type_u8 output_index_u32 amount_u64
				AddData(encodeLE64(800)).   // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_0).          // expected output_index = 0
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_1).          // expected type = LOCAL (1)
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}, {0x01}}, // k=0, j=0, source=1 (output)
			valid:  true,
		},

		// OP_INSPECTASSETGROUPSUM - inputs
		{
			name: "OP_INSPECTASSETGROUPSUM - group 0 input sum = 1500",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddData(encodeLE64(1500)).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}}, // k=0, source=0 (inputs)
			valid:  true,
		},
		// OP_INSPECTASSETGROUPSUM - outputs
		{
			name: "OP_INSPECTASSETGROUPSUM - group 0 output sum = 1500",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddData(encodeLE64(1500)).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x01}}, // k=0, source=1 (outputs)
			valid:  true,
		},
		// OP_INSPECTASSETGROUPSUM - both
		{
			name: "OP_INSPECTASSETGROUPSUM - group 0 both sums",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTASSETGROUPSUM).
				AddData(encodeLE64(1500)).    // output sum
				AddOp(OP_EQUALVERIFY).
				AddData(encodeLE64(1500)).    // input sum
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x02}}, // k=0, source=2 (both)
			valid:  true,
		},

		// OP_INSPECTOUTASSETCOUNT
		{
			name: "OP_INSPECTOUTASSETCOUNT - output 0 has 1 asset",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTOUTASSETCOUNT).
				AddOp(OP_1).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // o=0
			valid:  true,
		},

		// OP_INSPECTOUTASSETAT
		{
			name: "OP_INSPECTOUTASSETAT - output 0, asset 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTOUTASSETAT).
				// stack: txid32 gidx_u16 amount_u64
				AddData(encodeLE64(800)).       // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_0).              // expected gidx = 0
				AddOp(OP_EQUALVERIFY).
				AddData(testAssetTxid[:]). // expected txid
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}}, // o=0, t=0
			valid:  true,
		},

		// OP_INSPECTOUTASSETLOOKUP - found
		{
			name: "OP_INSPECTOUTASSETLOOKUP - found at output 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddData(encodeLE64(800)).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, testAssetTxid[:], {0x00}}, // o=0, txid, gidx=0
			valid:  true,
		},
		// OP_INSPECTOUTASSETLOOKUP - not found
		{
			name: "OP_INSPECTOUTASSETLOOKUP - not found returns -1",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTOUTASSETLOOKUP).
				AddOp(OP_1NEGATE).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, make([]byte, 32), {0x09}}, // o=0, zero txid, gidx=9
			valid:  true,
		},

		// OP_INSPECTINASSETCOUNT
		{
			name: "OP_INSPECTINASSETCOUNT - input 0 has 1 asset",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTINASSETCOUNT).
				AddOp(OP_1).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // i=0
			valid:  true,
		},

		// OP_INSPECTINASSETAT
		{
			name: "OP_INSPECTINASSETAT - input 0, asset 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTINASSETAT).
				// stack: txid32 gidx_u16 amount_u64
				AddData(encodeLE64(1000)).       // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_0).               // expected gidx = 0
				AddOp(OP_EQUALVERIFY).
				AddData(testAssetTxid[:]). // expected txid
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}}, // i=0, t=0
			valid:  true,
		},

		// OP_INSPECTINASSETLOOKUP - found
		{
			name: "OP_INSPECTINASSETLOOKUP - found at input 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddData(encodeLE64(1000)).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, testAssetTxid[:], {0x00}}, // i=0, txid, gidx=0
			valid:  true,
		},
		// OP_INSPECTINASSETLOOKUP - not found
		{
			name: "OP_INSPECTINASSETLOOKUP - not found returns -1",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTINASSETLOOKUP).
				AddOp(OP_1NEGATE).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, make([]byte, 32), {0x09}}, // i=0, zero txid, gidx=9
			valid:  true,
		},

		// OP_INSPECTGROUPINTENTOUTCOUNT
		{
			name: "OP_INSPECTGROUPINTENTOUTCOUNT - group 0 has 1 intent output",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTOUTCOUNT).
				AddOp(OP_1).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // k=0
			valid:  true,
		},
		{
			name: "OP_INSPECTGROUPINTENTOUTCOUNT - group 1 has 0 intent outputs",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTOUTCOUNT).
				AddOp(OP_0).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x01}}, // k=1
			valid:  true,
		},

		// OP_INSPECTGROUPINTENTOUT
		{
			name: "OP_INSPECTGROUPINTENTOUT - group 0, intent out 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTOUT).
				// stack: output_index_u32 amount_u64
				AddData(encodeLE64(700)).    // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_1).           // expected output_index = 1
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}}, // k=0, j=0
			valid:  true,
		},
		{
			name: "OP_INSPECTGROUPINTENTOUT - out of range",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTOUT),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x05}}, // k=0, j=5 (out of range)
			valid:  false,
		},

		// OP_INSPECTGROUPINTENTINCOUNT
		{
			name: "OP_INSPECTGROUPINTENTINCOUNT - group 0 has 1 intent input",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTINCOUNT).
				AddOp(OP_1).
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}}, // k=0
			valid:  true,
		},

		// OP_INSPECTGROUPINTENTIN
		{
			name: "OP_INSPECTGROUPINTENTIN - group 0, intent in 0",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTIN).
				// stack: txid_32 output_index_u32 amount_u64
				AddData(encodeLE64(500)).         // expected amount
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2).                // expected output_index = 2
				AddOp(OP_EQUALVERIFY).
				AddData(testIntentTxid[:]). // expected txid
				AddOp(OP_EQUAL),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x00}}, // k=0, j=0
			valid:  true,
		},
		{
			name: "OP_INSPECTGROUPINTENTIN - out of range",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTGROUPINTENTIN),
			packet: makeTestAssetPacket(),
			stack:  [][]byte{{0x00}, {0x05}}, // k=0, j=5 (out of range)
			valid:  false,
		},
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {
			Value: 1000000000,
			PkScript: []byte{
				OP_1, OP_DATA_32,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
		},
	})

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			script, err := tc.script.Script()
			if err != nil {
				tt.Fatalf("Script build failed: %v", err)
			}

			tx := makeTestTx()
			engine, err := NewEngine(
				script, tx, 0,
				txscript.StandardVerifyFlags&txscript.ScriptVerifyTaproot,
				txscript.NewSigCache(100),
				txscript.NewTxSigHashes(tx, prevoutFetcher),
				0, prevoutFetcher,
			)
			if err != nil {
				tt.Fatalf("NewEngine failed: %v", err)
			}

			engine.SetAssetPacket(tc.packet)
			if len(tc.stack) > 0 {
				engine.SetStack(tc.stack)
			}

			err = engine.Execute()
			if tc.valid && err != nil {
				tt.Errorf("Execute failed (expected success): %v", err)
			}
			if !tc.valid && err == nil {
				tt.Errorf("Execute succeeded (expected failure)")
			}

			if tc.valid && err == nil && tc.expectStack != nil {
				gotStack := engine.GetStack()
				if len(gotStack) != len(tc.expectStack) {
					tt.Errorf("Stack length mismatch: got %d, want %d", len(gotStack), len(tc.expectStack))
				} else {
					for i, expected := range tc.expectStack {
						if !bytes.Equal(gotStack[i], expected) {
							tt.Errorf("Stack[%d] mismatch: got %x, want %x", i, gotStack[i], expected)
						}
					}
				}
			}
		})
	}
}

// TestAssetOpcodeGroupIndexValidation tests that all group-index opcodes
// properly reject invalid indices.
func TestAssetOpcodeGroupIndexValidation(t *testing.T) {
	t.Parallel()

	// Opcodes that take a group index k from the stack
	groupOpcodes := []struct {
		name   string
		opcode byte
		stack  [][]byte // extra stack items beyond group index
	}{
		{"OP_INSPECTASSETGROUPASSETID", OP_INSPECTASSETGROUPASSETID, nil},
		{"OP_INSPECTASSETGROUPCTRL", OP_INSPECTASSETGROUPCTRL, nil},
		{"OP_INSPECTASSETGROUPMETADATAHASH", OP_INSPECTASSETGROUPMETADATAHASH, nil},
		{"OP_INSPECTASSETGROUPNUM", OP_INSPECTASSETGROUPNUM, [][]byte{{0x00}}},       // source=0
		{"OP_INSPECTASSETGROUPSUM", OP_INSPECTASSETGROUPSUM, [][]byte{{0x00}}},        // source=0
		{"OP_INSPECTGROUPINTENTOUTCOUNT", OP_INSPECTGROUPINTENTOUTCOUNT, nil},
		{"OP_INSPECTGROUPINTENTINCOUNT", OP_INSPECTGROUPINTENTINCOUNT, nil},
	}

	packet := makeTestAssetPacket()

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {
			Value: 1000000000,
			PkScript: []byte{
				OP_1, OP_DATA_32,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			},
		},
	})

	for _, tc := range groupOpcodes {
		t.Run(fmt.Sprintf("%s_invalid_index", tc.name), func(tt *testing.T) {
			script, err := txscript.NewScriptBuilder().AddOp(tc.opcode).Script()
			if err != nil {
				tt.Fatalf("Script build failed: %v", err)
			}

			tx := makeTestTx()
			engine, err := NewEngine(
				script, tx, 0,
				txscript.StandardVerifyFlags&txscript.ScriptVerifyTaproot,
				txscript.NewSigCache(100),
				txscript.NewTxSigHashes(tx, prevoutFetcher),
				0, prevoutFetcher,
			)
			if err != nil {
				tt.Fatalf("NewEngine failed: %v", err)
			}

			engine.SetAssetPacket(packet)

			// Build stack: k=99 (invalid), then any extra items
			stackItems := [][]byte{{99}} // invalid group index
			stackItems = append(stackItems, tc.stack...)
			engine.SetStack(stackItems)

			err = engine.Execute()
			if err == nil {
				tt.Errorf("Execute should have failed with invalid group index")
			}
		})
	}
}
