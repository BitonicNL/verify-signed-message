package bip322

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
)

// This file is adapted from the btcd package (v0.26.0) message transaction (msgtx) implementation and babylon package (v4.5.0) bip322 implementation.
//
// Original source:
//   - https://github.com/btcsuite/btcd/blob/v0.26.0/wire/msgtx.go
//   - https://github.com/babylonlabs-io/babylon/blob/v4.5.0/crypto/bip322/witness.go

// Constants related to witness data handling.
const (
	// maxWitnessItemsPerInput is the maximum number of witness items to be read for the witness data for a single TxIn.
	// This value is derived to ensure that the transaction weight cannot exceed the consensus limit.
	maxWitnessItemsPerInput = 4_000_000

	// maxWitnessItemSize is the maximum allowed size for an item within an input's witness data.
	// This value is bounded by the largest possible block size post-SegWit v1 (Taproot).
	maxWitnessItemSize = 4_000_000

	// defaultWitnessAlloc is the conservative initial allocation size for a transaction's witness stack.
	// Its value is the same as txscript.MaxStackSize because that is a useful and realistic upper bound for the number of witness items on a valid transaction.
	defaultWitnessAlloc = 1_000
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

	// Prevent a possible memory exhaustion attack by limiting the witCount value to a sane upper bound.
	if witCount > maxWitnessItemsPerInput {
		return nil, fmt.Errorf("too many witness items to fit into max message size [count %d, max %d]", witCount, maxWitnessItemsPerInput)
	}

	// To avoid a trivial memory allocation of maxWitnessItems elements with a single varInt claiming that number of items without providing them, pre-allocate with a much smaller size.
	allocCount := min(witCount, defaultWitnessAlloc)

	// Read each stack item from the buffer.
	witnessStack := make([][]byte, 0, allocCount)
	for range witCount {
		witnessItem, err := readScript(buf, maxWitnessItemSize, buf.Len(), "script witness item")
		if err != nil {
			return nil, err
		}
		witnessStack = append(witnessStack, witnessItem)
	}

	return witnessStack, nil
}

// readScript reads a variable length byte array that represents a witness stack item.
// It is encoded as a varInt containing the length of the array followed by the bytes themselves.
// This function provides protection against memory exhaustion attacks and malformed messages.
//
// For more information, refer: https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
func readScript(r io.Reader, maxAllowed uint32, remaining int, fieldName string) ([]byte, error) {
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// Ensure that the byte array is within the maximum allowed size to prevent memory exhaustion attacks.
	if count > uint64(maxAllowed) {
		return nil, fmt.Errorf("%s is larger than the max allowed size [count %d, max %d]", fieldName, count, maxAllowed)
	}

	// Ensure the claimed item length fits in the remaining unread bytes to prevent allocating a buffer for bytes that were never provided.
	// remaining is a buffer length and never negative.
	if remaining < 0 || count > uint64(remaining) {
		return nil, fmt.Errorf("%s exceeds remaining buffer capacity [count %d, remaining %d]", fieldName, count, remaining)
	}

	// Read the byte array.
	b := make([]byte, count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
