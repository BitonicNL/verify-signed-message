package bip322_test

import (
	"encoding/base64"
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal/bip322"
)

// This input decodes to a varint count of 4,000,000, which passes the item-count bound but would previously trigger an ~96 MB preallocation before failing on the truncated data. Assert the bounded allocation stays far below that.
func TestSimpleSigToWitnessCountAmplification(t *testing.T) {
	t.Parallel()

	sig, err := base64.StdEncoding.DecodeString("/gAJPQA=")
	require.NoError(t, err)
	require.Len(t, sig, 5)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err = bip322.SimpleSigToWitness(sig)
	require.Error(t, err)

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	require.Less(t, allocated, uint64(8<<20))
}

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
