package internal_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal"
)

func TestCreateMagicMessage(t *testing.T) {
	message := internal.CreateMagicMessage("random message")
	require.Equal(t, "\x18Bitcoin Signed Message:\n\x0Erandom message", message)
}
