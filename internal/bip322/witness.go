package bip322

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
)

// This file is adapted from the btcd package (v0.24.0) message transaction (msgtx) implementation and babylon package (v0.8.5) bip322 implementation.
//
// Original source:
//   - https://github.com/btcsuite/btcd/blob/v0.24.0/wire/msgtx.go#L559-L590
//   - https://github.com/babylonchain/babylon/blob/v0.8.5/crypto/bip322/witness.go

// Constants related to witness data handling.
const (
	// maxWitnessItemsPerInput is the maximum number of witness items to be read for the witness data for a single TxIn.
	// This value is derived to ensure that the transaction weight cannot exceed the consensus limit.
	maxWitnessItemsPerInput = 4_000_000

	// maxWitnessItemSize is the maximum allowed size for an item within an input's witness data.
	// This value is bounded by the largest possible block size post-SegWit v1 (Taproot).
	maxWitnessItemSize = 4_000_000
)

// SimpleSigToWitness converts a simple signature into a witness stack.
// As per the BIP-322 spec, a simple signature consists of a witness stack, consensus encoded as a vector of vectors of bytes.
// For more details, refer: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#simple
//
// The encoding of the witness stack is based on the Leather wallet implementation.
// For details, refer: https://github.com/leather-wallet/extension/blob/dev/src/shared/crypto/bitcoin/bip322/bip322-utils.ts#L58
//
// The signature is encoded as follows:
// - 1st byte: Elements of the witness stack that are serialized
// - For each element of the stack
//   - The first byte specifies how many bytes it contains
//   - The rest are the bytes of the element
func SimpleSigToWitness(sig []byte) ([][]byte, error) {
	// Create a buffer from the input signature.
	buf := bytes.NewBuffer(sig)

	// Read the varint encoding the number of stack items.
	witCount, err := wire.ReadVarInt(buf, 0)
	if err != nil {
		return nil, err
	}

	// Ensure that the number of stack items is within the maximum allowed limit.
	if witCount > maxWitnessItemsPerInput {
		return nil, fmt.Errorf("too many witness items to fit into max message size [count %d, max %d]", witCount, maxWitnessItemsPerInput)
	}

	// Read each stack item from the buffer.
	witnessStack := make([][]byte, witCount)
	for j := uint64(0); j < witCount; j++ {
		witnessStack[j], err = readScript(buf, 0, maxWitnessItemSize, "script witness item")
		if err != nil {
			return nil, err
		}
	}

	return witnessStack, nil
}

// readScript reads a variable length byte array that represents a transaction script.
// It is encoded as a varInt containing the length of the array followed by the bytes themselves.
// This function provides protection against memory exhaustion attacks and malformed messages.
//
// For more information, refer: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
func readScript(r io.Reader, pver, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := wire.ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	// Ensure that the byte array is within the maximum allowed size to prevent memory exhaustion attacks.
	if count > uint64(maxAllowed) {
		return nil, fmt.Errorf("%s is larger than the max allowed size [count %d, max %d]", fieldName, count, maxAllowed)
	}

	// Read the byte array.
	b := make([]byte, count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
