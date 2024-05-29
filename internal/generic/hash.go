package generic

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/samber/lo"

	"github.com/bitonicnl/verify-signed-message/internal/generic/flags"
)

// GeneratePublicKeyHash returns the public key hash, either compressed or uncompressed, depending on the recovery flag.
func GeneratePublicKeyHash(recoveryFlag int, publicKey *btcec.PublicKey) []byte {
	if lo.Contains[int](flags.Uncompressed(), recoveryFlag) {
		return btcutil.Hash160(publicKey.SerializeUncompressed())
	}

	return btcutil.Hash160(publicKey.SerializeCompressed())
}
