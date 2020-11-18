package signature_test

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal"
	"github.com/bitonicnl/verify-signed-message/internal/signature"
)

// uint8 representation of `H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=`
var signatureEncoded = []uint8{
	31, 248, 158, 195, 243, 97, 29, 95, 85, 244, 199, 84, 18, 127, 203, 20, 231, 237, 105, 60, 181,
	138, 241, 143, 40, 242, 178, 50, 90, 252, 57, 42, 36, 52, 46, 249, 229, 240, 49, 165, 36, 225, 53,
	24, 175, 193, 51, 108, 201, 143, 111, 61, 64, 211, 69, 128, 79, 115, 103, 38, 25, 222, 93, 227, 46,
}

// Static representation of the public key for `14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY`
var publicKey = &btcec.PublicKey{
	Curve: btcec.S256(),
	X:     new(big.Int).SetBits([]big.Word{15911006285554725158, 3973652043348564759, 17029311123882767650, 5593478405199673976}),
	Y:     new(big.Int).SetBits([]big.Word{3658760562191262475, 11449388996567004868, 877373473855763687, 15711380188339738643}),
}

func TestParseCompactInvalid(t *testing.T) {
	btcecSig, err := signature.ParseCompact([]byte{}, btcec.S256())
	require.EqualError(t, err, "invalid compact signature size")
	require.Nil(t, btcecSig)
}

func TestParseCompact(t *testing.T) {
	btcecSig, err := signature.ParseCompact(signatureEncoded, btcec.S256())
	require.NoError(t, err)
	require.Equal(t, "112454100686917088716763005039207074580155840372180209748670933598947425987108", btcecSig.R.String())
	require.Equal(t, "23603267825273168310009216611640910854054822424267934178492474518750065713966", btcecSig.S.String())
}

func TestVerifyInvalidPublicKey(t *testing.T) {
	err := signature.Verify(signatureEncoded, &btcec.PublicKey{}, []byte{})
	require.EqualError(t, err, "public key was not correctly instantiated")
}

func TestVerifyInvalidEncodedSignature(t *testing.T) {
	key, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	err = signature.Verify([]byte{}, (*btcec.PublicKey)(&key.PublicKey), []byte{})
	require.EqualError(t, err, "invalid compact signature size")
}

func TestVerifyInvalidSignature(t *testing.T) {
	key, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	err = signature.Verify(signatureEncoded, (*btcec.PublicKey)(&key.PublicKey), []byte{})
	require.EqualError(t, err, "signature could not be verified")
}

func TestVerifyInvalidMessage(t *testing.T) {
	magicMessage := internal.CreateMagicMessage("INVALID")
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	require.EqualError(t, signature.Verify(signatureEncoded, publicKey, messageHash), "signature could not be verified")
}

func TestVerify(t *testing.T) {
	magicMessage := internal.CreateMagicMessage("test message")
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	require.NoError(t, signature.Verify(signatureEncoded, publicKey, messageHash))
}
