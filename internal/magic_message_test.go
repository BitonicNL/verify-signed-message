package internal_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal"
)

func TestCreateMagicMessage(t *testing.T) {
	t.Parallel()

	message := internal.CreateMagicMessage("random message")
	require.Equal(t, "\x18Bitcoin Signed Message:\n\x0Erandom message", message)
}

// Test vectors taken from https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#message-hashing
func TestCreateMagicMessageBIP322(t *testing.T) {
	t.Parallel()

	msgHash := internal.CreateMagicMessageBIP322([]byte{})
	msgHashHex := hex.EncodeToString(msgHash[:])
	require.Equal(t, "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1", msgHashHex)

	msgHash = internal.CreateMagicMessageBIP322([]byte("Hello World"))
	msgHashHex = hex.EncodeToString(msgHash[:])
	require.Equal(t, "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a", msgHashHex)
}
