package internal

import (
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/samber/lo"

	"github.com/bitonicnl/verify-signed-message/internal/flags"
)

// ValidateP2PKH ensures that the passed P2PKH address matches the address generated from the public key hash, recovery flag and network.
func ValidateP2PKH(recoveryFlag int, pubkeyHash []byte, addr btcutil.Address, net *chaincfg.Params) (bool, error) {
	// Ensure proper address type will be generated
	if lo.Contains[int](flags.TrezorP2WPKHAndP2SH(), recoveryFlag) {
		return false, errors.New("cannot use P2PKH for recovery flag 'BIP137 (Trezor) P2WPKH-P2SH'")
	} else if lo.Contains[int](flags.TrezorP2WPKH(), recoveryFlag) {
		return false, errors.New("cannot use P2PKH for recovery flag 'BIP137 (Trezor) P2WPKH'")
	}

	if p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubkeyHash, net); err != nil {
		return false, err
	} else if addr.String() != p2pkhAddr.String() {
		return false, fmt.Errorf("generated address '%s' does not match expected address '%s'", p2pkhAddr.String(), addr.String())
	}

	return true, nil
}

// ValidateP2PKH ensures that the passed P2SH address matches the address generated from the public key hash, recovery flag and network.
func ValidateP2SH(recoveryFlag int, pubkeyHash []byte, addr btcutil.Address, net *chaincfg.Params) (bool, error) {
	// Ensure proper address type will be generated
	if lo.Contains[int](flags.Uncompressed(), recoveryFlag) {
		return false, errors.New("cannot use P2SH for recovery flag 'P2PKH uncompressed'")
	} else if lo.Contains[int](flags.TrezorP2WPKH(), recoveryFlag) {
		return false, errors.New("cannot use P2SH for recovery flag 'BIP137 (Trezor) P2WPKH'")
	}

	if scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(pubkeyHash).Script(); err != nil {
		return false, err
	} else if p2shAddr, err := btcutil.NewAddressScriptHash(scriptSig, net); err != nil {
		return false, err
	} else if addr.String() != p2shAddr.String() {
		return false, fmt.Errorf("generated address '%s' does not match expected address '%s'", p2shAddr.String(), addr.String())
	}

	return true, nil
}

// ValidateP2WPKH ensures that the passed P2WPKH address matches the address generated from the public key hash, recovery flag and network.
func ValidateP2WPKH(recoveryFlag int, pubkeyHash []byte, addr btcutil.Address, net *chaincfg.Params) (bool, error) {
	// Ensure proper address type will be generated
	if lo.Contains[int](flags.Uncompressed(), recoveryFlag) {
		return false, errors.New("cannot use P2WPKH for recovery flag 'P2PKH uncompressed'")
	}

	if p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubkeyHash, net); err != nil {
		return false, err
	} else if addr.String() != p2wkhAddr.String() {
		return false, fmt.Errorf("generated address '%s' does not match expected address '%s'", p2wkhAddr.String(), addr.String())
	}

	return true, nil
}

// ValidateP2TR ensures that the passed P2TR address matches the address generated from the public key hash, recovery flag and network.
func ValidateP2TR(recoveryFlag int, pubKey *btcec.PublicKey, addr btcutil.Address, net *chaincfg.Params) (bool, error) {
	// Ensure proper address type will be generated
	if lo.Contains[int](flags.Uncompressed(), recoveryFlag) {
		return false, errors.New("cannot use P2TR for recovery flag 'P2TR uncompressed'")
	}
	tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)
	if p2trAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), net); err != nil {
		return false, err
	} else if addr.String() != p2trAddr.String() {
		return false, fmt.Errorf("generated address '%s' does not match expected address '%s'", p2trAddr.String(), addr.String())
	}

	return true, nil
}
