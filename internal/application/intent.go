package application

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitIntent aims to execute arkade scripts on unsigned intent proof
// it must be used before registration of the intent
func (s *service) SubmitIntent(ctx context.Context, intent Intent) (*psbt.Packet, error) {
	if err := validateRegisterMessage(intent.Message); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	ptx := &intent.Proof.Packet

	prevoutFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	signerPublicKey := s.signer.secretKey.PubKey()

	for inputIndex := range ptx.Inputs {
		if inputIndex == 0 {
			// in intent proof, input index 0 is the message input
			// the signature script equals to the input 1 script
			// so we can skip it and handle it later if input index 1 is an arkade script
			continue
		}

		script, err := readArkadeScript(ptx, inputIndex, signerPublicKey)
		if err != nil {
			// skip if the input is not an arkade script
			continue
		}

		if err := script.execute(ptx.UnsignedTx, prevoutFetcher, inputIndex); err != nil {
			log.WithError(err).WithField("input_index", inputIndex).Error("arkade script execution failed")
			return nil, fmt.Errorf("failed to execute arkade script at input %d: %w", inputIndex, err)
		}

		if err := s.signer.signInput(ptx, inputIndex, script.hash, prevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

		// if input index 1 is valid and signed, we can also sign the intent message input (index 0)
		if inputIndex == 1 {
			if err := s.signer.signInput(ptx, 0, script.hash, prevoutFetcher); err != nil {
				return nil, fmt.Errorf("failed to sign fake message input: %w", err)
			}
		}
	}

	return ptx, nil
}

func validateRegisterMessage(message intent.RegisterMessage) error {
	now := time.Now()
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if expireAt.Before(now) {
			return fmt.Errorf("intent message expired")
		}
	}

	if message.ValidAt > 0 {
		validAt := time.Unix(message.ValidAt, 0)
		if validAt.After(now) {
			return fmt.Errorf("intent message not valid yet")
		}
	}

	return nil
}
