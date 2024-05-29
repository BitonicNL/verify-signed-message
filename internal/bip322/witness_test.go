package bip322_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal/bip322"
)

func TestSimpleSigToWitness(t *testing.T) {
	t.Parallel()

	signatureEncoded := "AkcwRAIgbAFRpM0rhdBlXr7qe5eEf3XgSeausCm2XTmZVxSYpcsCIDcbR87wF9DTrvdw1czYEEzOjso52dOSaw8VrC4GgzFRASECO5NGNFlPClJnTHNDW94h7pPL5D7xbl6FBNTrGaYpYcA="
	emptyBytesSig, err := base64.StdEncoding.DecodeString(signatureEncoded)
	require.NoError(t, err)

	witness, err := bip322.SimpleSigToWitness(emptyBytesSig)
	require.NoError(t, err)
	require.Len(t, witness, 2)

	firstWitness := hex.EncodeToString(witness[0])
	require.Equal(t, "304402206c0151a4cd2b85d0655ebeea7b97847f75e049e6aeb029b65d3999571498a5cb0220371b47cef017d0d3aef770d5ccd8104cce8eca39d9d3926b0f15ac2e0683315101", firstWitness)

	secondWitness := hex.EncodeToString(witness[1])
	require.Equal(t, "023b934634594f0a52674c73435bde21ee93cbe43ef16e5e8504d4eb19a62961c0", secondWitness)
}
