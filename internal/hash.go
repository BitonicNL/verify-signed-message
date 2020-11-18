package internal

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/thoas/go-funk"

	"github.com/bitonicnl/verify-signed-message/internal/flags"
)

// Returns the public key hash, either compressed or uncompressed based on the recovery flag
func GeneratePublicKeyHash(recoveryFlag int, pubKey *btcec.PublicKey) []byte {
	if funk.ContainsInt(flags.Uncompressed(), recoveryFlag) {
		return btcutil.Hash160(pubKey.SerializeUncompressed())
	}

	return btcutil.Hash160(pubKey.SerializeCompressed())
}
