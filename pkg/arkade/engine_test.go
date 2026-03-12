// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package arkade

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
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

	// Pre-compute the expected tx hash for OP_TXID tests
	txForHash := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			},
		},
	}
	expectedTxHash := txForHash.TxHash()

	// A wrong hash to test negative case
	wrongHash := chainhash.Hash{0x01}

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
				AddOp(OP_DIV64).                                                 // stack: [remainder, quotient, flag]
				AddOp(OP_1).                                                     // success flag
				AddOp(OP_EQUALVERIFY).                                           // stack: [remainder, quotient]
				AddData([]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}). // 3 in LE64 (quotient)
				AddOp(OP_EQUALVERIFY).                                           // stack: [remainder]
				AddOp(OP_DROP).                                                  // drop remainder, stack: []
				AddOp(OP_TRUE),                                                  // leave truthy value for clean stack
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
				AddOp(OP_NEG64).                                                 // stack: [a, 0]
				AddData([]byte{0x00}).                                           // overflow flag
				AddOp(OP_EQUALVERIFY).                                           // stack: [a]
				AddOp(OP_DROP).                                                  // drop restored operand
				AddOp(OP_TRUE),                                                  // leave truthy value for clean stack
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
			name: "OP_TXID",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXID).
				AddData(expectedTxHash[:]).
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
			name: "OP_TXID_LENGTH",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXID).
				AddOp(OP_SIZE).
				AddOp(OP_NIP).
				AddData([]byte{0x20}). // 32 bytes
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
			name: "OP_TXID_WRONG_HASH",
			script: txscript.NewScriptBuilder().
				AddOp(OP_TXID).
				AddData(wrongHash[:]).
				AddOp(OP_EQUAL),
			cases: []testCase{
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


func TestMerkleBranchVerify(t *testing.T) {
	t.Parallel()

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

	simpleTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
			},
		},
	}

	// --- Helper: sort-and-combine for branch hash ---
	sortedBranchHash := func(branchTag, left, right []byte) []byte {
		combined := make([]byte, 64)
		if bytes.Compare(left, right) < 0 {
			copy(combined[:32], left)
			copy(combined[32:], right)
		} else {
			copy(combined[:32], right)
			copy(combined[32:], left)
		}
		h := chainhash.TaggedHash(branchTag, combined)
		return h[:]
	}

	leafTag := []byte("ArkadeLeaf")
	branchTag := []byte("ArkadeBranch")

	// ---- 2-leaf tree: "hello", "world" ----
	leafA2 := chainhash.TaggedHash(leafTag, []byte("hello"))
	leafB2 := chainhash.TaggedHash(leafTag, []byte("world"))
	root2Leaf := sortedBranchHash(branchTag, leafA2[:], leafB2[:])

	// ---- 4-leaf tree: "alpha", "beta", "gamma", "delta" ----
	hashA := chainhash.TaggedHash(leafTag, []byte("alpha"))
	hashB := chainhash.TaggedHash(leafTag, []byte("beta"))
	hashC := chainhash.TaggedHash(leafTag, []byte("gamma"))
	hashD := chainhash.TaggedHash(leafTag, []byte("delta"))

	hashAB := sortedBranchHash(branchTag, hashA[:], hashB[:])
	hashCD := sortedBranchHash(branchTag, hashC[:], hashD[:])
	rootABCD := sortedBranchHash(branchTag, hashAB, hashCD)

	// Proof for leaf "alpha": [hashB, hashCD]
	proofAlpha := make([]byte, 64)
	copy(proofAlpha[:32], hashB[:])
	copy(proofAlpha[32:], hashCD)

	// Proof for leaf "beta": [hashA, hashCD]
	proofBeta := make([]byte, 64)
	copy(proofBeta[:32], hashA[:])
	copy(proofBeta[32:], hashCD)

	// ---- Single leaf: "only" ----
	singleLeafRoot := chainhash.TaggedHash(leafTag, []byte("only"))

	// ---- Raw hash mode vectors ----
	// Use leafA2 as a pre-computed 32-byte hash, treat it as raw leaf_data
	rawLeafData := leafA2[:]                                              // 32 bytes
	rawSibling := leafB2[:]                                               // 32 bytes
	rawRoot := sortedBranchHash(branchTag, rawLeafData[:], rawSibling[:]) // root in raw mode

	// ---- Proof chaining vectors ----
	// Build a 4-leaf tree but prove via chaining:
	// First call: prove "alpha" in left subtree -> produces hashAB (sub-root)
	// Second call: use hashAB as raw leaf_data with proof=[hashCD] -> produces rootABCD
	chainSubProof := make([]byte, 32)
	copy(chainSubProof, hashB[:]) // proof for alpha in left subtree

	chainUpperProof := make([]byte, 32)
	copy(chainUpperProof, hashCD) // proof for sub-root in full tree

	// --- Helper to build engine and run ---
	runTest := func(tt *testing.T, script []byte, stack [][]byte) error {
		tt.Helper()
		engine, err := NewEngine(
			script,
			simpleTx, 0,
			txscript.NewSigCache(100),
			txscript.NewTxSigHashes(simpleTx, prevoutFetcher),
			0,
			prevoutFetcher,
		)
		if err != nil {
			tt.Fatalf("NewEngine failed: %v", err)
		}
		engine.SetStack(stack)
		return engine.Execute()
	}

	type testCase struct {
		name    string
		valid   bool
		script  func(t *testing.T) []byte
		stack   [][]byte
		errText string // substring expected in error (for invalid cases)
	}

	tests := []testCase{
		// ---- Test 1: valid 2-leaf tree ----
		{
			name:  "valid_2leaf_tree",
			valid: true,
			script: func(t *testing.T) []byte {
				// OP_MERKLEBRANCHVERIFY <expected_root> OP_EQUALVERIFY OP_TRUE
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(root2Leaf).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag (bottom)
				branchTag,       // branch_tag
				leafB2[:],       // proof = sibling hash
				[]byte("hello"), // leaf_data (top)
			},
		},
		// ---- Test 2: valid 4-leaf tree ----
		{
			name:  "valid_4leaf_tree",
			valid: true,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rootABCD).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag (bottom)
				branchTag,       // branch_tag
				proofAlpha,      // proof = [hashB, hashCD] (64 bytes)
				[]byte("alpha"), // leaf_data (top)
			},
		},
		// ---- Test 3: valid single leaf, empty proof ----
		{
			name:  "valid_single_leaf_empty_proof",
			valid: true,
			script: func(t *testing.T) []byte {
				// Root = tagged_hash(leafTag, "only") since proof is empty
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(singleLeafRoot[:]).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,        // leaf_tag (bottom)
				branchTag,      // branch_tag
				{},             // empty proof
				[]byte("only"), // leaf_data (top)
			},
		},
		// ---- Test 4: valid raw hash mode (empty leaf_tag) ----
		{
			name:  "valid_raw_hash_mode",
			valid: true,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rawRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				{},           // empty leaf_tag -> raw hash mode
				branchTag,    // branch_tag
				rawSibling,   // proof = sibling
				rawLeafData,  // leaf_data = 32 bytes (pre-computed hash)
			},
		},
		// ---- Test 5: valid proof chaining ----
		// First OP_MERKLEBRANCHVERIFY: prove "alpha" in left subtree -> pushes hashAB
		// Then set up raw mode args and call again -> pushes rootABCD
		{
			name:  "valid_proof_chaining",
			valid: true,
			script: func(t *testing.T) []byte {
				// Stack before: [leafTag, branchTag, chainSubProof, "alpha"]
				// After 1st MERKLEBRANCHVERIFY: [..., hashAB]
				// Then we push: OP_0 (empty leaf_tag for raw mode), branchTag, chainUpperProof
				// Then: 3 OP_ROLL to bring hashAB to top as leaf_data
				// After 2nd MERKLEBRANCHVERIFY: [..., rootABCD]
				// Then: <rootABCD> OP_EQUALVERIFY OP_TRUE
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddOp(OP_0).
					AddData(branchTag).
					AddData(chainUpperProof).
					AddOp(OP_3).
					AddOp(OP_ROLL).
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rootABCD).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag for first call
				branchTag,       // branch_tag for first call
				chainSubProof,   // proof for alpha in left subtree
				[]byte("alpha"), // leaf_data
			},
		},
		// ---- Test 6: valid two leaves same tree, verify roots match ----
		// Prove "alpha" and "beta" in same 4-leaf tree, check roots equal
		{
			name:  "valid_two_leaf_same_tree",
			valid: true,
			script: func(t *testing.T) []byte {
				// Stack before: [leafTag, branchTag, proofAlpha, "alpha"]
				// 1st MERKLEBRANCHVERIFY -> pushes rootABCD (from alpha)
				// Then push items for beta proof inline:
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(leafTag).
					AddData(branchTag).
					AddData(proofBeta).
					AddData([]byte("beta")).
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,         // leaf_tag for first call (bottom)
				branchTag,       // branch_tag for first call
				proofAlpha,      // proof for alpha
				[]byte("alpha"), // leaf_data for first call (top)
			},
		},
		// ---- Test 7: invalid wrong root ----
		{
			name:  "invalid_wrong_root",
			valid: false,
			script: func(t *testing.T) []byte {
				wrongRoot := make([]byte, 32) // all zeros
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(wrongRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,
				branchTag,
				leafB2[:],
				[]byte("hello"),
			},
			errText: "EQUALVERIFY",
		},
		// ---- Test 8: invalid proof not multiple of 32 ----
		{
			name:  "invalid_proof_not_multiple_of_32",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(root2Leaf).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,
				branchTag,
				make([]byte, 33), // 33 bytes, not multiple of 32
				[]byte("hello"),
			},
			errText: "proof length",
		},
		// ---- Test 9: invalid empty branch_tag ----
		{
			name:  "invalid_empty_branch_tag",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(root2Leaf).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				leafTag,
				{},          // empty branch_tag
				leafB2[:],
				[]byte("hello"),
			},
			errText: "branch_tag",
		},
		// ---- Test 10: invalid raw mode leaf not 32 bytes (10 bytes) ----
		{
			name:  "invalid_raw_mode_leaf_not_32_bytes",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rawRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				{},                    // empty leaf_tag -> raw hash mode
				branchTag,
				rawSibling,
				make([]byte, 10),      // only 10 bytes, must be 32 in raw mode
			},
			errText: "leaf_data",
		},
		// ---- Test 11: invalid raw mode leaf 31 bytes ----
		{
			name:  "invalid_empty_leaf_tag_nonempty_but_wrong_size",
			valid: false,
			script: func(t *testing.T) []byte {
				s, err := txscript.NewScriptBuilder().
					AddOp(OP_MERKLEBRANCHVERIFY).
					AddData(rawRoot).
					AddOp(OP_EQUALVERIFY).
					AddOp(OP_TRUE).
					Script()
				if err != nil {
					t.Fatalf("script build: %v", err)
				}
				return s
			},
			stack: [][]byte{
				{},                    // empty leaf_tag -> raw hash mode
				branchTag,
				rawSibling,
				make([]byte, 31),      // 31 bytes, must be 32 in raw mode
			},
			errText: "leaf_data",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			script := tc.script(tt)

			err := runTest(tt, script, tc.stack)
			if tc.valid && err != nil {
				tt.Errorf("Execute failed: %v", err)
			}
			if !tc.valid && err == nil {
				tt.Errorf("Execute should have failed")
			}
			if !tc.valid && err != nil && tc.errText != "" {
				if !strings.Contains(err.Error(), tc.errText) {
					tt.Errorf("Expected error containing %q, got: %v", tc.errText, err)
				}
			}
		})
	}
}

func TestIntrospectorPacketOpcodes(t *testing.T) {
	t.Parallel()

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		{Hash: chainhash.Hash{}, Index: 0}: {Value: 1000, PkScript: []byte{
			OP_1, OP_DATA_32,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},
		{Hash: chainhash.Hash{}, Index: 1}: {Value: 2000, PkScript: []byte{
			OP_1, OP_DATA_32,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},
	})

	twoInputTx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}},
			{PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 1}},
		},
	}

	scriptA := []byte{OP_TRUE}
	scriptB := []byte{OP_1, OP_1, OP_ADD}
	witnessA := wire.TxWitness{{0xaa, 0xbb}}

	packet, err := NewPacket(
		IntrospectorEntry{Vin: 0, Script: scriptA, Witness: witnessA},
		IntrospectorEntry{Vin: 1, Script: scriptB, Witness: nil},
	)
	if err != nil {
		t.Fatalf("NewPacket: %v", err)
	}

	expectedScriptHashA := ArkadeScriptHash(scriptA)
	expectedScriptHashB := ArkadeScriptHash(scriptB)
	var witBuf bytes.Buffer
	_ = psbt.WriteTxWitness(&witBuf, witnessA)
	expectedWitnessHashA := chainhash.TaggedHash(TagArkWitnessHash, witBuf.Bytes())
	zeroHash := make([]byte, 32)

	runEngine := func(t *testing.T, script []byte, tx *wire.MsgTx, pkt IntrospectorPacket, stack [][]byte) error {
		t.Helper()
		engine, err := NewEngine(
			script, tx, 0,
			txscript.NewSigCache(100),
			txscript.NewTxSigHashes(tx, prevoutFetcher),
			1000, prevoutFetcher,
		)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		if pkt != nil {
			engine.SetIntrospectorPacket(pkt)
		}
		if len(stack) > 0 {
			engine.SetStack(stack)
		}
		return engine.Execute()
	}

	type tc struct {
		name    string
		valid   bool
		script  []byte
		tx      *wire.MsgTx
		pkt     IntrospectorPacket
		stack   [][]byte
		errText string
	}

	scriptHashCheck := func(t *testing.T, index byte, expected []byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(index).
			AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
			AddData(expected).
			AddOp(OP_EQUAL).
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	witnessHashCheck := func(t *testing.T, index byte, expected []byte) []byte {
		t.Helper()
		s, err := txscript.NewScriptBuilder().
			AddOp(index).
			AddOp(OP_INSPECTINPUTARKADEWITNESSHASH).
			AddData(expected).
			AddOp(OP_EQUAL).
			Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	buildScript := func(t *testing.T, ops ...byte) []byte {
		t.Helper()
		b := txscript.NewScriptBuilder()
		for _, op := range ops {
			b.AddOp(op)
		}
		s, err := b.Script()
		if err != nil {
			t.Fatalf("script build: %v", err)
		}
		return s
	}

	tests := []tc{
		{
			name:   "script_hash_own_input",
			valid:  true,
			script: scriptHashCheck(t, OP_0, expectedScriptHashA),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:   "script_hash_sibling_input",
			valid:  true,
			script: scriptHashCheck(t, OP_1, expectedScriptHashB),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name: "script_hash_equality_across_inputs",
			valid: true,
			script: func() []byte {
				s, _ := txscript.NewScriptBuilder().
					AddOp(OP_0).AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
					AddOp(OP_0).AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
					AddOp(OP_EQUAL).
					Script()
				return s
			}(),
			tx:  twoInputTx,
			pkt: packet,
		},
		{
			name:    "script_hash_no_packet",
			valid:   false,
			script:  buildScript(t, OP_0, OP_INSPECTINPUTARKADESCRIPTHASH),
			tx:      twoInputTx,
			pkt:     nil,
			errText: "no introspector packet",
		},
		{
			name:    "script_hash_out_of_range",
			valid:   false,
			script:  buildScript(t, OP_2, OP_INSPECTINPUTARKADESCRIPTHASH),
			tx:      twoInputTx,
			pkt:     packet,
			errText: "input index out of range",
		},
		{
			name:  "script_hash_missing_entry",
			valid: false,
			script: func() []byte {
				s, _ := txscript.NewScriptBuilder().
					AddOp(OP_0).
					AddOp(OP_INSPECTINPUTARKADESCRIPTHASH).
					Script()
				return s
			}(),
			tx: twoInputTx,
			pkt: IntrospectorPacket{
				{Vin: 1, Script: scriptB},
			},
			errText: "no introspector entry for vin 0",
		},
		{
			name:   "witness_hash_non_empty",
			valid:  true,
			script: witnessHashCheck(t, OP_0, expectedWitnessHashA[:]),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:   "witness_hash_empty_returns_zeros",
			valid:  true,
			script: witnessHashCheck(t, OP_1, zeroHash),
			tx:     twoInputTx,
			pkt:    packet,
		},
		{
			name:    "witness_hash_no_packet",
			valid:   false,
			script:  buildScript(t, OP_0, OP_INSPECTINPUTARKADEWITNESSHASH),
			tx:      twoInputTx,
			pkt:     nil,
			errText: "no introspector packet",
		},
		{
			name:    "witness_hash_out_of_range",
			valid:   false,
			script:  buildScript(t, OP_2, OP_INSPECTINPUTARKADEWITNESSHASH),
			tx:      twoInputTx,
			pkt:     packet,
			errText: "input index out of range",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := runEngine(t, tt.script, tt.tx, tt.pkt, tt.stack)
			if tt.valid && err != nil {
				t.Errorf("expected success, got: %v", err)
			}
			if !tt.valid {
				if err == nil {
					t.Error("expected failure, got success")
				} else if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("expected error containing %q, got: %v", tt.errText, err)
				}
			}
		})
	}
}
