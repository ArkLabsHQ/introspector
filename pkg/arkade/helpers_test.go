package arkade

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// testArkPrevOutFetcher is a test-only implementation of ArkPrevOutFetcher.
type testArkPrevOutFetcher struct {
	txscript.PrevOutputFetcher
	arkTxs map[wire.OutPoint]*wire.MsgTx
}

func newTestArkPrevOutFetcher(base txscript.PrevOutputFetcher, arkTxs map[wire.OutPoint]*wire.MsgTx) *testArkPrevOutFetcher {
	return &testArkPrevOutFetcher{
		PrevOutputFetcher: base,
		arkTxs:            arkTxs,
	}
}

func (f *testArkPrevOutFetcher) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if f.arkTxs == nil {
		return nil
	}
	return f.arkTxs[op]
}
