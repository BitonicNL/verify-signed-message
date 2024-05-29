package generic

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/samber/lo"

	"github.com/bitonicnl/verify-signed-message/internal"
	"github.com/bitonicnl/verify-signed-message/internal/generic/flags"
	"github.com/bitonicnl/verify-signed-message/internal/generic/signature"
)

// ExpectedSignatureLength contains the fixed signature length all signed messages are expected to have.
const ExpectedSignatureLength = 65

func Verify(address btcutil.Address, message string, signatureDecoded []byte, net *chaincfg.Params) (bool, error) {
	// Ensure signature has proper length
	if len(signatureDecoded) != ExpectedSignatureLength {
		return false, fmt.Errorf("wrong signature length: %d instead of %d", len(signatureDecoded), ExpectedSignatureLength)
	}

	// Ensure signature has proper recovery flag
	recoveryFlag := int(signatureDecoded[0])
	if !lo.Contains[int](flags.All(), recoveryFlag) {
		return false, fmt.Errorf("invalid recovery flag: %d", recoveryFlag)
	}

	// Should address be compressed (for checking later)
	compressed := flags.ShouldBeCompressed(recoveryFlag)

	// Reset recovery flag after obtaining keyID for Trezor
	if lo.Contains[int](flags.Trezor(), recoveryFlag) {
		signatureDecoded[0] = byte(27 + flags.GetKeyID(recoveryFlag))
	}

	// Make and hash the message
	messageHash := chainhash.DoubleHashB([]byte(internal.CreateMagicMessage(message)))

	// Recover the public key from signature and message hash
	publicKey, wasCompressed, err := ecdsa.RecoverCompact(signatureDecoded, messageHash)
	if err != nil {
		return false, fmt.Errorf("could not recover pubkey: %w", err)
	}

	// Ensure our initial assumption was correct, except for Trezor as they do something different
	if compressed != wasCompressed && !lo.Contains[int](flags.Trezor(), recoveryFlag) {
		return false, errors.New("we expected the key to be compressed, it wasn't")
	}

	// Verify that the signature is valid
	// TODO: ecdsa.RecoverCompact already does all, check if we can just remove it
	if err := signature.Verify(signatureDecoded, publicKey, messageHash); err != nil {
		return false, err
	}

	// Get the hash from the public key, so we can check that address matches
	publicKeyHash := GeneratePublicKeyHash(recoveryFlag, publicKey)

	switch address.(type) {
	// Validate P2PKH - Legacy
	case *btcutil.AddressPubKeyHash:
		return ValidateP2PKH(recoveryFlag, publicKeyHash, address, net)
	// Validate P2SH-P2WPKH - Segwit
	case *btcutil.AddressScriptHash:
		return ValidateP2SH(recoveryFlag, publicKeyHash, address, net)
	// Validate P2WPKH - Native Segwit
	case *btcutil.AddressWitnessPubKeyHash:
		return ValidateP2WPKH(recoveryFlag, publicKeyHash, address, net)
	// Validate P2TR - Taproot
	case *btcutil.AddressTaproot:
		return ValidateP2TR(recoveryFlag, publicKey, address, net)
	// Unsupported address
	default:
		return false, fmt.Errorf("unsupported address type '%s'", reflect.TypeOf(address))
	}
}
