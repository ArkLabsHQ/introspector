package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArkLabsHQ/introspector/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitOnchainTx executes arkade scripts on a plain Bitcoin PSBT and signs
// every input whose tapscript closure contains the introspector's tweaked
// key. Per-input context (including the optional PrevoutTxField for
// prev-tx introspection opcodes) lives in PSBT unknown fields.
func (s *service) SubmitOnchainTx(ctx context.Context, tx OnchainTx) (*psbt.Packet, error) {
	ptx := tx.Tx

	prevOutFetcher, err := prevOutFetcherForOnchainTxFromPSBT(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	packet, err := arkade.FindIntrospectorPacket(ptx.UnsignedTx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse introspector packet: %w", err)
	}
	if len(packet) == 0 {
		return nil, fmt.Errorf("no introspector packet found in transaction")
	}

	signerPublicKey := s.signer.secretKey.PubKey()
	nSigned := 0

	for _, entry := range packet {
		inputIndex := int(entry.Vin)

		script, err := arkade.ReadArkadeScript(ptx, signerPublicKey, entry)
		if err != nil {
			if errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) && len(ptx.Inputs) > 1 {
				continue
			}
			return nil, fmt.Errorf("failed to read arkade script: %w vin=%d", err, inputIndex)
		}

		log.Debugf("executing arkade script: %x", script.Script())
		if err := script.Execute(ptx.UnsignedTx, prevOutFetcher, inputIndex); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w vin=%d", err, inputIndex)
		}
		log.Debugf("execution of %x succeeded", script.Script())

		if err := s.signer.signInput(ptx, inputIndex, script.Hash(), prevOutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		nSigned++
	}

	if nSigned == 0 {
		return nil, fmt.Errorf("failed to find any valid input/entry pairs")
	}

	return ptx, nil
}
