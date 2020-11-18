package verifier

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/thoas/go-funk"

	"github.com/bitonicnl/verify-signed-message/internal"
	"github.com/bitonicnl/verify-signed-message/internal/flags"
	"github.com/bitonicnl/verify-signed-message/internal/signature"
)

// All signed messages must have a fixed signature length.
const ExpectedSignatureLength = 65

// Verify will verify a Signature based on the recovery flag on Bitcoin mainnet.
func Verify(sig SignedMessage) (bool, error) {
	return VerifyWithChain(sig, &chaincfg.MainNetParams)
}

// Verify will either return true if the signature is valid or an error.
func VerifyWithChain(sig SignedMessage, net *chaincfg.Params) (bool, error) {
	// Check if message contains spaces that can be trimmed, if so run the verification with the trimmed message
	// This is required because Electrum trims messages before signing
	if trimmedMessage := strings.TrimSpace(sig.Message); len(sig.Message) != len(trimmedMessage) {
		// We only care about this return if it's valid
		if verified, err := Verify(SignedMessage{Message: trimmedMessage, Address: sig.Address, Signature: sig.Signature}); err == nil && verified {
			return true, nil
		}
	}

	// Decode the address
	addr, err := btcutil.DecodeAddress(sig.Address, net)
	if err != nil {
		return false, fmt.Errorf("could not decode address: %s", err)
	}

	// Decode the signature
	signatureEncoded, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return false, err
	}

	// Ensure signature has proper length
	if len(signatureEncoded) != ExpectedSignatureLength {
		return false, fmt.Errorf("wrong signature length: %d instead of 65", len(signatureEncoded))
	}

	// Ensure signature has proper recovery flag
	recoveryFlag := int(signatureEncoded[0])
	if !funk.ContainsInt(flags.All(), recoveryFlag) {
		return false, fmt.Errorf("invalid recovery flag: %d", recoveryFlag)
	}

	// Retrieve KeyID
	keyID := flags.GetKeyID(recoveryFlag)

	// Should address be compressed (for checking later)
	compressed := flags.ShouldBeCompressed(recoveryFlag)

	// Reset recovery flag after obtaining keyID for Trezor
	if funk.ContainsInt(flags.Trezor(), recoveryFlag) {
		signatureEncoded[0] = byte(27 + keyID)
	}

	// Make the magic message
	magicMessage := internal.CreateMagicMessage(sig.Message)

	// Hash the message
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	// Recover the pubkey from signature and message hash
	pubKey, comp, err := btcec.RecoverCompact(btcec.S256(), signatureEncoded, messageHash)
	if err != nil {
		return false, fmt.Errorf("could not recover pubkey: %s", err)
	}

	// Ensure our initial assumption was correct, except for Trezor as they do something different
	if compressed != comp && !funk.ContainsInt(flags.Trezor(), recoveryFlag) {
		return false, errors.New("we expected the key to be compressed, it wasn't")
	}

	// Verify that the signature is valid
	if err := signature.Verify(signatureEncoded, pubKey, messageHash); err != nil {
		return false, err
	}

	// Get the hash from the public key, so we can check that address matches
	pubkeyHash := internal.GeneratePublicKeyHash(recoveryFlag, pubKey)

	// Validate P2PKH
	if _, ok := addr.(*btcutil.AddressPubKeyHash); ok {
		return internal.ValidateP2PKH(recoveryFlag, pubkeyHash, addr, net)
	}

	// Validate P2SH
	if _, ok := addr.(*btcutil.AddressScriptHash); ok {
		return internal.ValidateP2SH(recoveryFlag, pubkeyHash, addr, net)
	}

	// Validate P2WPKH
	if _, ok := addr.(*btcutil.AddressWitnessPubKeyHash); ok {
		return internal.ValidateP2WPKH(recoveryFlag, pubkeyHash, addr, net)
	}

	// Catch all, should never happen
	return false, fmt.Errorf("unexpected address type '%s'", reflect.TypeOf(addr))
}
