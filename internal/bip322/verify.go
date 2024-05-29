package bip322

import (
	"errors"
	"fmt"
	"reflect"

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
