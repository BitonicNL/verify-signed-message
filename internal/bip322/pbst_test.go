package bip322_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal/bip322"
)

// Taken from https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#transaction-hashes
func TestGetToSignTx(t *testing.T) {
	t.Parallel()

	testAddr := "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
	testAddrDecoded, err := btcutil.DecodeAddress(testAddr, &chaincfg.TestNet3Params)
	require.NoError(t, err)

	toSpendTx, err := bip322.BuildToSpendTx([]byte{}, testAddrDecoded)
	require.NoError(t, err)
	require.Equal(t, "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7", toSpendTx.TxHash().String())
	toSignTx := bip322.BuildToSignTx(toSpendTx)
	require.Equal(t, "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6", toSignTx.TxHash().String())

	toSpendTx, err = bip322.BuildToSpendTx([]byte("Hello World"), testAddrDecoded)
	require.NoError(t, err)
	require.Equal(t, "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b", toSpendTx.TxHash().String())
	toSignTx = bip322.BuildToSignTx(toSpendTx)
	require.Equal(t, "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf", toSignTx.TxHash().String())
}
