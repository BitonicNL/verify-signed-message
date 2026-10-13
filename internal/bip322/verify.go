package bip322

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
)

// TODO: Check if we can implement more by referencing https://github.com/ACken2/bip322-js/blob/main/src/Verifier.ts#L23
// Their implementation supports *btcutil.AddressScriptHash (but no multisig, yet).
func Verify(address btcutil.Address, message string, signatureDecoded []byte) (bool, error) {
	// Ensure we support the address
	if !IsSupported(address) {
		return false, fmt.Errorf("unsupported address type '%s'", reflect.TypeOf(address))
	}

	// Draft corresponding toSpend and toSign transaction using the message and script pubkey
	toSpend, err := BuildToSpendTx([]byte(message), address)
	if err != nil {
		return false, fmt.Errorf("could not build spending transaction: %w", err)
	}

	witness, err := SimpleSigToWitness(signatureDecoded)
	if err != nil {
		return false, fmt.Errorf("error converting signature into witness: %w", err)
	}

	// BIP-322 requires SIGHASH_ALL (or SIGHASH_DEFAULT for taproot), but the btcd engine accepts any sighash mode, so enforce the restriction ourselves.
	if err := checkSigHash(address, witness); err != nil {
		return false, err
	}

	toSign := BuildToSignTx(toSpend)
	toSign.TxIn[0].Witness = witness

	// Validate toSign transaction
	if len(toSign.TxIn) != 1 || len(toSign.TxOut) != 1 {
		return false, errors.New("invalid toSign transaction format")
	}

	// From the rules here:
	// https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#verification-process
	// We only need to perform verification of whether toSign spends toSpend properly
	// given that the signature is a simple one, and we construct both toSpend and toSign
	inputFetcher := txscript.NewCannedPrevOutputFetcher(toSpend.TxOut[0].PkScript, 0)
	sigHashes := txscript.NewTxSigHashes(toSign, inputFetcher)
	vm, err := txscript.NewEngine(toSpend.TxOut[0].PkScript, toSign, 0, txscript.StandardVerifyFlags, txscript.NewSigCache(0), sigHashes, toSpend.TxOut[0].Value, inputFetcher)
	if err != nil {
		return false, fmt.Errorf("could not create new engine: %w", err)
	}

	// Execute the script
	err = vm.Execute()
	if err != nil {
		return false, fmt.Errorf("script execution failed: %w", err)
	}

	// Verification successful
	return true, nil
}

// checkSigHash enforces BIP-322's sighash restriction for the supported (P2WPKH and P2TR key-path) output types: SIGHASH_ALL is required, except taproot which also accepts SIGHASH_DEFAULT.
func checkSigHash(address btcutil.Address, witness [][]byte) error {
	if len(witness) == 0 {
		return nil
	}

	// The signature is the first witness item for both supported output types.
	rawSig := witness[0]
	if len(rawSig) == 0 {
		return nil
	}

	switch address.(type) {
	// P2WPKH: ECDSA signature with an explicit trailing sighash byte.
	case *btcutil.AddressWitnessPubKeyHash:
		hashType := txscript.SigHashType(rawSig[len(rawSig)-1])
		if hashType != txscript.SigHashAll {
			return fmt.Errorf("invalid signature: BIP-322 requires SIGHASH_ALL for P2WPKH, got sighash type 0x%02x", hashType)
		}

	// P2TR: Schnorr signature, 64 bytes (implicit SIGHASH_DEFAULT) or 65 bytes with an explicit trailing sighash byte.
	case *btcutil.AddressTaproot:
		hashType := txscript.SigHashDefault
		if len(rawSig) == schnorr.SignatureSize+1 {
			hashType = txscript.SigHashType(rawSig[schnorr.SignatureSize])
		}
		if hashType != txscript.SigHashAll && hashType != txscript.SigHashDefault {
			return fmt.Errorf("invalid signature: BIP-322 requires SIGHASH_ALL or SIGHASH_DEFAULT for P2TR, got sighash type 0x%02x", hashType)
		}
	}

	return nil
}

func IsSupported(address btcutil.Address) bool {
	switch address.(type) {
	// P2WPKH - Native Segwit
	case *btcutil.AddressWitnessPubKeyHash:
		return true
	// P2TR - Taproot
	case *btcutil.AddressTaproot:
		return true
	default:
		return false
	}
}
