// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package arkade

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestNewOpcodes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		valid       bool
		tx          *wire.MsgTx
		txIdx       int
		inputAmount int64
		stack       [][]byte
	}

	type fixture struct {
		name   string
		script *txscript.ScriptBuilder
		cases  []testCase
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{
			Hash:  chainhash.Hash{},
			Index: 0,
		}: {
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

	tests := []fixture{
		{
			name:   "OP_MOD",
			script: txscript.NewScriptBuilder().AddOp(OP_4).AddOp(OP_3).AddOp(OP_MOD).AddOp(OP_1).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name:   "OP_DIV",
			script: txscript.NewScriptBuilder().AddOp(OP_DIV).AddOp(OP_3).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x06}, {0x02}},
				},
				{
					valid: false,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x00}, // Divisor of 0 should fail
						{0x01},
					},
				},
			},
		},
		{
			name:   "OP_MUL",
			script: txscript.NewScriptBuilder().AddOp(OP_MUL).AddOp(OP_6).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x02}, {0x03}}, // 2 * 3 = 6
				},
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       [][]byte{{0x06}, {0x01}}, // 6 * 1 = 6
				},
			},
		},
		{
			name:   "OP_XOR",
			script: txscript.NewScriptBuilder().AddOp(OP_XOR).AddOp(OP_6).AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x05}, // 5 (0101)
						{0x03}, // 3 (0011)
						// 5 XOR 3 = 6 (0110)
					},
				},
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack: [][]byte{
						{0x0F}, // 15 (1111)
						{0x09}, // 9  (1001)
						// 15 XOR 9 = 6 (0110)
					},
				},
			},
		},
		{
			name: "OP_CAT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02}).
				AddData([]byte{0x03, 0x04}).
				AddOp(OP_CAT).
				AddData([]byte{0x01, 0x02, 0x03, 0x04}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUBSTR",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03, 0x04}).
				AddData([]byte{0x01}).
				AddData([]byte{0x02}).
				AddOp(OP_SUBSTR).
				AddData([]byte{0x02, 0x03}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LEFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03}).
				AddData([]byte{0x02}).
				AddOp(OP_LEFT).
				AddData([]byte{0x01, 0x02}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_RIGHT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x02, 0x03}).
				AddData([]byte{0x02}).
				AddOp(OP_RIGHT).
				AddData([]byte{0x02, 0x03}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INVERT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0xFF}).
				AddOp(OP_INVERT).
				AddData([]byte{0xFF, 0x00}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_AND",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06}). // 0110
				AddData([]byte{0x0C}). // 1100
				AddOp(OP_AND).
				AddData([]byte{0x04}). // 0100
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_OR",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x07}). // 0111
				AddData([]byte{0x05}). // 0101
				AddOp(OP_OR).
				AddData([]byte{0x07}). // 0111
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LSHIFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03}). // 0011
				AddData([]byte{0x01}). // Shift by 1
				AddOp(OP_LSHIFT).
				AddData([]byte{0x06}). // 0110 (shifted left by 1)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_RSHIFT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06}). // 0110
				AddData([]byte{0x01}). // Shift by 1
				AddOp(OP_RSHIFT).
				AddData([]byte{0x03}). // 0011 (shifted right by 1)
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_ADD64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_ADD64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_ADD64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}). // Max positive int64
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_ADD64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2DROP). // drop restored operands
				AddOp(OP_TRUE),  // leave truthy value for clean stack
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUB64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_SUB64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SUB64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}). // Min negative int64 (-9223372036854775808)
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_SUB64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2DROP). // drop restored operands
				AddOp(OP_TRUE),  // leave truthy value for clean stack
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_MUL64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_MUL64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 6 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_MUL64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}). // Max positive int64
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_MUL64).
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY).
				AddOp(OP_2DROP). // drop restored operands
				AddOp(OP_TRUE),  // leave truthy value for clean stack
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_DIV64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 6 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_DIV64).       // stack: [remainder, quotient, flag]
				AddOp(OP_1).           // success flag
				AddOp(OP_EQUALVERIFY). // stack: [remainder, quotient]
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64 (quotient)
				AddOp(OP_EQUALVERIFY). // stack: [remainder]
				AddOp(OP_DROP).        // drop remainder, stack: []
				AddOp(OP_TRUE),        // leave truthy value for clean stack
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_NEG64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_NEG64).
				AddOp(OP_1). // success flag
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{0xFD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}). // -3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_NEG64_OVERFLOW",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}). // Min negative int64
				AddOp(OP_NEG64).       // stack: [a, 0]
				AddData([]byte{0x00}). // overflow flag
				AddOp(OP_EQUALVERIFY). // stack: [a]
				AddOp(OP_DROP).        // drop restored operand
				AddOp(OP_TRUE),        // leave truthy value for clean stack
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LESSTHAN64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_LESSTHAN64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LESSTHANOREQUAL64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_LESSTHANOREQUAL64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_GREATERTHAN64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 1 in LE64
				AddOp(OP_GREATERTHAN64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_GREATERTHANOREQUAL64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddData([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 2 in LE64
				AddOp(OP_GREATERTHANOREQUAL64).
				AddData([]byte{0x01}). // true
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_SCRIPTNUMTOLE64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03}). // ScriptNum 3
				AddOp(OP_SCRIPTNUMTOLE64).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LE64TOSCRIPTNUM",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_LE64TOSCRIPTNUM).
				AddData([]byte{0x03}). // ScriptNum 3
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_LE32TOLE64",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x03, 0x00, 0x00, 0x00}). // 3 in LE32
				AddOp(OP_LE32TOLE64).
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTOUTPOINT",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}). // success flag
				AddOp(OP_INSPECTINPUTOUTPOINT).
				AddData([]byte{0x00}). // Index
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}). // Hash
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTVALUE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTVALUE).
				AddData([]byte{0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00}). // 1000000000 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 1000000000,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSCRIPTPUBKEY",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTSCRIPTPUBKEY).
				AddOp(OP_1). // segwit v1
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{ // witness program
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTINPUTSEQUENCE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTINPUTSEQUENCE).
				AddData([]byte{0xFF, 0xFF, 0xFF, 0xFF}). // Max sequence number
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
								Sequence: 4294967295,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_PUSHCURRENTINPUTINDEX",
			script: txscript.NewScriptBuilder().
				AddOp(OP_PUSHCURRENTINPUTINDEX).
				AddData([]byte{0x00}). // Input index 0
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTVALUE",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTOUTPUTVALUE).
				AddData([]byte{0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00}). // 1000000000 in LE64
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
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
							{
								Value:    1000000000,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTOUTPUTSCRIPTPUBKEY",
			script: txscript.NewScriptBuilder().
				AddData([]byte{0x00}).
				AddOp(OP_INSPECTOUTPUTSCRIPTPUBKEY).
				AddOp(OP_1). // Expected scriptPubKey
				AddOp(OP_EQUALVERIFY).
				AddData([]byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
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
							{
								Value: 0,
								PkScript: []byte{
									OP_1, OP_DATA_32,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTVERSION",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTVERSION).
				AddData([]byte{0x01, 0x00, 0x00, 0x00}). // Version 1 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTLOCKTIME",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTLOCKTIME).
				AddData([]byte{0x00, 0x00, 0x00, 0x00}). // LockTime 0 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
						LockTime: 0,
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTNUMINPUTS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMINPUTS).
				AddOp(OP_1). // 1 input
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_INSPECTNUMOUTPUTS",
			script: txscript.NewScriptBuilder().
				AddOp(OP_INSPECTNUMOUTPUTS).
				AddData([]byte{0x01}). // 1 output
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
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
							{
								Value:    0,
								PkScript: nil,
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_TXWEIGHT",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXWEIGHT).
				AddData([]byte{0xCC, 0x00, 0x00, 0x00}). // Expected weight 204 in LE32
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "OP_CHECKSIGFROMSTACK",
			script: txscript.NewScriptBuilder().
				AddData([]byte{ // signature
					0xE9, 0x07, 0x83, 0x1F, 0x80, 0x84, 0x8D, 0x10,
					0x69, 0xA5, 0x37, 0x1B, 0x40, 0x24, 0x10, 0x36,
					0x4B, 0xDF, 0x1C, 0x5F, 0x83, 0x07, 0xB0, 0x08,
					0x4C, 0x55, 0xF1, 0xCE, 0x2D, 0xCA, 0x82, 0x15,
					0x25, 0xF6, 0x6A, 0x4A, 0x85, 0xEA, 0x8B, 0x71,
					0xE4, 0x82, 0xA7, 0x4F, 0x38, 0x2D, 0x2C, 0xE5,
					0xEB, 0xEE, 0xE8, 0xFD, 0xB2, 0x17, 0x2F, 0x47,
					0x7D, 0xF4, 0x90, 0x0D, 0x31, 0x05, 0x36, 0xC0,
				}).
				AddData([]byte{ // message
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}).
				AddData([]byte{ // public key
					0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
					0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
					0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
					0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9,
				}).
				AddOp(OP_CHECKSIGFROMSTACK),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
		{
			name: "SHA256_STREAMING",
			script: txscript.NewScriptBuilder().
				AddData([]byte("Hello")).   // stack = [Hello]
				AddOp(OP_SHA256INITIALIZE). // stack = [shactx(Hello)]
				AddData([]byte(" World")).  // stack = [shactx(Hello), World]
				AddOp(OP_SHA256UPDATE).     // stack = [shactx(Hello+World)]
				AddData([]byte("!")).       // stack = [shactx(Hello+World), !]
				AddOp(OP_SHA256FINALIZE).   // stack = [sha256(Hello+World+!)]
				AddData([]byte{
					0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
					0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
					0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
					0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69,
				}).
				AddOp(OP_EQUAL),
			cases: []testCase{
				{
					valid: true,
					tx: &wire.MsgTx{
						Version: 1,
						TxIn: []*wire.TxIn{
							{
								PreviousOutPoint: wire.OutPoint{
									Hash:  chainhash.Hash{},
									Index: 0,
								},
							},
						},
					},
					txIdx:       0,
					inputAmount: 0,
					stack:       nil,
				},
			},
		},
	}

	for _, test := range tests {
		for caseIndex, c := range test.cases {
			t.Run(fmt.Sprintf("%s_%d", test.name, caseIndex), func(tt *testing.T) {
				script, err := test.script.Script()
				if err != nil {
					tt.Errorf("NewEngine failed: %v", err)
				}

				engine, err := NewEngine(
					script,
					c.tx, c.txIdx,
					txscript.NewSigCache(100),
					txscript.NewTxSigHashes(c.tx, prevoutFetcher),
					c.inputAmount,
					prevoutFetcher,
				)
				if err != nil {
					tt.Errorf("NewEngine failed: %v", err)
				}

				if len(c.stack) > 0 {
					engine.SetStack(c.stack)
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

