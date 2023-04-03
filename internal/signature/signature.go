package signature

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Values taken from `ecdsa`.
const (
	// compactSigSize is the size of a compact signature.  It consists of a
	// compact signature recovery code byte followed by the R and S components
	// serialized as 32-byte big-endian values. 1+32*2 = 65.
	// for the R and S components. 1+32+32=65.
	compactSigSize = 65

	// compactSigMagicOffset is a value used when creating the compact signature
	// recovery code inherited from Bitcoin and has no meaning, but has been
	// retained for compatibility.  For historical purposes, it was originally
	// picked to avoid a binary representation that would allow compact
	// signatures to be mistaken for other components.
	compactSigMagicOffset = 27

	// compactSigCompPubKey is a value used when creating the compact signature
	// recovery code to indicate the original public key was compressed.
	compactSigCompPubKey = 4
)

// ParseCompact attempts to recover the ecdsa.Signature from the provided
// compact signature. The logic for this was taken from `ecdsa.RecoverCompact`
// as it is not exposed publicly.
func ParseCompact(signature []byte) (*ecdsa.Signature, error) {
	// A compact signature consists of a recovery byte followed by the R and
	// S components serialized as 32-byte big-endian values.
	if len(signature) != compactSigSize {
		return nil, errors.New("invalid compact signature size")
	}

	// Parse and validate the compact signature recovery code.
	const (
		minValidCode = compactSigMagicOffset
		maxValidCode = compactSigMagicOffset + compactSigCompPubKey + 3
	)
	if signature[0] < minValidCode || signature[0] > maxValidCode {
		return nil, errors.New("invalid compact signature recovery code")
	}

	// Parse and validate the R and S signature components.
	//
	// Fail if r and s are not in [1, N-1].
	var r, s btcec.ModNScalar
	if overflow := r.SetByteSlice(signature[1:33]); overflow {
		return nil, errors.New("signature R is >= curve order")
	}
	if r.IsZero() {
		return nil, errors.New("signature R is 0")
	}
	if overflow := s.SetByteSlice(signature[33:]); overflow {
		return nil, errors.New("signature S is >= curve order")
	}
	if s.IsZero() {
		return nil, errors.New("signature S is 0")
	}

	return ecdsa.NewSignature(&r, &s), nil
}

// Verify ensures that the signature for the message hash is valid for the public key given.
func Verify(signatureEncoded []byte, publicKey *btcec.PublicKey, messageHash []byte) error {
	if publicKey == nil || !publicKey.IsOnCurve() {
		return errors.New("public key was not correctly instantiated")
	}

	// Parse the signature so we can verify it
	parsedSignature, err := ParseCompact(signatureEncoded)
	if err != nil {
		return err
	}

	// Actually verify the message
	if verified := parsedSignature.Verify(messageHash, publicKey); !verified {
		return errors.New("signature could not be verified")
	}

	return nil
}
