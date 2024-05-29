package verifier

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/bitonicnl/verify-signed-message/internal/bip322"
	"github.com/bitonicnl/verify-signed-message/internal/generic"
)

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

	// Ensure the address is valid for the passed network
	if !address.IsForNet(net) {
		return false, fmt.Errorf("address '%s' is not valid for network '%s'", signedMessage.Address, net.Name)
	}

	// Decode the signature
	signatureDecoded, err := base64.StdEncoding.DecodeString(signedMessage.Signature)
	if err != nil {
		return false, fmt.Errorf("could not decode signature: %w", err)
	}

	// Handle generic/BIP-137 signature. For P2PKH address, assume the signature is also a legacy signature
	if _, ok := address.(*btcutil.AddressPubKeyHash); ok || len(signatureDecoded) == generic.ExpectedSignatureLength {
		return generic.Verify(address, signedMessage.Message, signatureDecoded, net)
	}

	// Otherwise, try and verify it as BIP-322
	return bip322.Verify(address, signedMessage.Message, signatureDecoded)
}
