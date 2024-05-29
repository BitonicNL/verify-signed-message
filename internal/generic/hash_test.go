package generic_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"

	"github.com/bitonicnl/verify-signed-message/internal/generic"
)

func TestGeneratePublicKeyHashCompressed(t *testing.T) {
	t.Parallel()

	// uint8 representation of `H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=`.
	signatureEncoded := []uint8{
		31, 248, 158, 195, 243, 97, 29, 95, 85, 244, 199, 84, 18, 127, 203, 20, 231, 237, 105, 60, 181,
		138, 241, 143, 40, 242, 178, 50, 90, 252, 57, 42, 36, 52, 46, 249, 229, 240, 49, 165, 36, 225, 53,
		24, 175, 193, 51, 108, 201, 143, 111, 61, 64, 211, 69, 128, 79, 115, 103, 38, 25, 222, 93, 227, 46,
	}

	// Grab the recovery flag from the signature
	recoveryFlag := int(signatureEncoded[0])

	// uint8 representation of the public key for `14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY`.
	publicKeyEncoded := []uint8{
		3, 77, 160, 6, 249, 88, 190, 186, 120, 236, 84, 68, 61, 244, 163, 245, 34, 55, 37, 63,
		122, 232, 203, 219, 23, 220, 207, 63, 234, 165, 127, 49, 38,
	}

	publicKey, err := btcec.ParsePubKey(publicKeyEncoded)
	require.NoError(t, err)

	expected := []byte{0x27, 0xc1, 0x74, 0x81, 0x4a, 0x24, 0x4a, 0x65, 0xac, 0xeb, 0xd3, 0xd, 0x74, 0xfa, 0x8d, 0x72, 0x37, 0x98, 0x47, 0x29}
	require.Equal(t, expected, generic.GeneratePublicKeyHash(recoveryFlag, publicKey))
}

func TestGeneratePublicKeyHash(t *testing.T) {
	t.Parallel()

	// uint8 representation of `G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=`.
	signatureEncoded := []uint8{
		27, 248, 158, 195, 243, 97, 29, 95, 85, 244, 199, 84, 18, 127, 203, 20, 231, 237, 105, 60, 181, 138, 241, 143,
		40, 242, 178, 50, 90, 252, 57, 42, 36, 52, 46, 249, 229, 240, 49, 165, 36, 225, 53, 24, 175, 193, 51,
		108, 201, 143, 111, 61, 64, 211, 69, 128, 79, 115, 103, 38, 25, 222, 93, 227, 46,
	}

	// Grab the recovery flag from the signature
	recoveryFlag := int(signatureEncoded[0])

	// uint8 representation of the public key for `1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD`.
	publicKeyEncoded := []uint8{
		4, 77, 160, 6, 249, 88, 190, 186, 120, 236, 84, 68, 61, 244, 163, 245, 34, 55, 37, 63, 122, 232, 203, 219, 23, 220, 207, 63, 234,
		165, 127, 49, 38, 218, 10, 9, 9, 241, 25, 152, 19, 12, 45, 14, 134, 164, 133, 244, 231, 158, 228, 102, 161, 131, 164, 118, 196,
		50, 198, 135, 88, 171, 158, 99, 11,
	}

	publicKey, err := btcec.ParsePubKey(publicKeyEncoded)
	require.NoError(t, err)

	expected := []byte{0xb4, 0xa5, 0xd3, 0x96, 0x4, 0x71, 0x56, 0x8c, 0x38, 0x83, 0x4, 0x6e, 0xec, 0x3b, 0x41, 0xb4, 0x95, 0x3d, 0x61, 0xa1}
	require.Equal(t, expected, generic.GeneratePublicKeyHash(recoveryFlag, publicKey))
}
