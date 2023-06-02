package verifier

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/samber/lo"

	"github.com/bitonicnl/verify-signed-message/internal"
	"github.com/bitonicnl/verify-signed-message/internal/flags"
	"github.com/bitonicnl/verify-signed-message/internal/signature"
)

// ExpectedSignatureLength contains the fixed signature length all signed messages are expected to have.
const ExpectedSignatureLength = 65

// Verify will verify a SignedMessage based on the recovery flag on Bitcoin main network.
func Verify(sig SignedMessage) (bool, error) {
	return VerifyWithChain(sig, &chaincfg.MainNetParams)
}

// VerifyWithChain will verify a SignedMessage based on the recovery flag on the passed network.
// Supported address types are P2PKH, P2WKH, NP2WKH (P2WPKH), P2TR.
func VerifyWithChain(signedMessage SignedMessage, net *chaincfg.Params) (bool, error) {
	// Check if message contains spaces that can be trimmed, if so run the verification with the trimmed message
	// This is required because Electrum trims messages before signing
	if trimmedMessage := strings.TrimSpace(signedMessage.Message); len(signedMessage.Message) != len(trimmedMessage) {
		// We only care about this return if it's valid
		if verified, err := Verify(SignedMessage{Message: trimmedMessage, Address: signedMessage.Address, Signature: signedMessage.Signature}); err == nil && verified {
			return true, nil
		}
	}

	// Decode the address
	address, err := btcutil.DecodeAddress(signedMessage.Address, net)
	if err != nil {
		return false, fmt.Errorf("could not decode address: %w", err)
	}

	// Decode the signature
	signatureEncoded, err := base64.StdEncoding.DecodeString(signedMessage.Signature)
	if err != nil {
		return false, err
	}

	// Ensure signature has proper length
	if len(signatureEncoded) != ExpectedSignatureLength {
		return false, fmt.Errorf("wrong signature length: %d instead of 65", len(signatureEncoded))
	}

	// Ensure signature has proper recovery flag
	recoveryFlag := int(signatureEncoded[0])
	if !lo.Contains[int](flags.All(), recoveryFlag) {
		return false, fmt.Errorf("invalid recovery flag: %d", recoveryFlag)
	}

	// Retrieve KeyID
	keyID := flags.GetKeyID(recoveryFlag)

	// Should address be compressed (for checking later)
	compressed := flags.ShouldBeCompressed(recoveryFlag)

	// Reset recovery flag after obtaining keyID for Trezor
	if lo.Contains[int](flags.Trezor(), recoveryFlag) {
		signatureEncoded[0] = byte(27 + keyID)
	}

	// Make the magic message
	magicMessage := internal.CreateMagicMessage(signedMessage.Message)

	// Hash the message
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	// Recover the public key from signature and message hash
	publicKey, comp, err := ecdsa.RecoverCompact(signatureEncoded, messageHash)
	if err != nil {
		return false, fmt.Errorf("could not recover pubkey: %w", err)
	}

	// Ensure our initial assumption was correct, except for Trezor as they do something different
	if compressed != comp && !lo.Contains[int](flags.Trezor(), recoveryFlag) {
		return false, errors.New("we expected the key to be compressed, it wasn't")
	}

	// Verify that the signature is valid
	if err := signature.Verify(signatureEncoded, publicKey, messageHash); err != nil {
		return false, err
	}

	// Get the hash from the public key, so we can check that address matches
	publicKeyHash := internal.GeneratePublicKeyHash(recoveryFlag, publicKey)

	switch address.(type) {
	// Validate P2PKH
	case *btcutil.AddressPubKeyHash:
		return internal.ValidateP2PKH(recoveryFlag, publicKeyHash, address, net)
	// Validate P2SH
	case *btcutil.AddressScriptHash:
		return internal.ValidateP2SH(recoveryFlag, publicKeyHash, address, net)
	// Validate P2WPKH
	case *btcutil.AddressWitnessPubKeyHash:
		return internal.ValidateP2WPKH(recoveryFlag, publicKeyHash, address, net)
	// Validate P2TR
	case *btcutil.AddressTaproot:
		return internal.ValidateP2TR(recoveryFlag, publicKey, address, net)
	// Unsupported address
	default:
		return false, fmt.Errorf("unsupported address type '%s'", reflect.TypeOf(address))
	}
}
