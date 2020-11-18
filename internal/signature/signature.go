package signature

import (
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// ParseCompact is taken from `btcec.RecoverCompact` as this part is not exposed anywhere else.
func ParseCompact(signature []byte, curve *btcec.KoblitzCurve) (*btcec.Signature, error) {
	bitLen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitLen*2 {
		return nil, errors.New("invalid compact signature size")
	}

	return &btcec.Signature{
		R: new(big.Int).SetBytes(signature[1 : bitLen+1]),
		S: new(big.Int).SetBytes(signature[bitLen+1:]),
	}, nil
}

// Verify checks if the signature for the message hash is valid for the public key given.
func Verify(signatureEncoded []byte, publicKey *btcec.PublicKey, messageHash []byte) error {
	if publicKey == nil || publicKey.Curve == nil {
		return errors.New("public key was not correctly instantiated")
	}

	// Parse the signature so we can verify it
	parsedSignature, err := ParseCompact(signatureEncoded, btcec.S256())
	if err != nil {
		return err
	}

	// Actually verify the message
	if verified := parsedSignature.Verify(messageHash, publicKey); !verified {
		return errors.New("signature could not be verified")
	}

	return nil
}
