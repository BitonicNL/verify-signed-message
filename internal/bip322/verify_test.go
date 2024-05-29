package bip322_test

import (
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/suite"

	"github.com/bitonicnl/verify-signed-message/internal/bip322"
	verifier "github.com/bitonicnl/verify-signed-message/pkg"
)

type VerifyTestSuite struct {
	suite.Suite
}

func TestVerifyTestSuite(t *testing.T) {
	// Run everything in parallel
	t.Parallel()

	suite.Run(t, new(VerifyTestSuite))
}

func (s *VerifyTestSuite) TestVerifyIncorrect() {
	tests := map[string]struct {
		signedMessage verifier.SignedMessage
		expectedError string
	}{
		// Taken from https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1774
		"native segwit - wrong address": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1qkecg9ly2xwxqgdy9egpuy87qc9x26smpts562s",
				Message:   "",
				Signature: "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
			},
			expectedError: "script execution failed: OP_EQUALVERIFY failed",
		},
		// Taken from https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1790
		"native segwit - malformed address": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
				Message:   "",
				Signature: "AkcwRAIgClVQ8S9yX1h8YThlGElD9lOrQbOwbFDjkYb0ebfiq+oCIDHgb/X9WNalNNtqTXb465ufbv9JuLxcJf8qi7DP6yOXASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
			},
			expectedError: "script execution failed: signature not empty on failed checksig",
		},
		// Taken from https://github.com/ACken2/bip322-js/blob/159456f44f31f0b38097b957bbe75c0eae4971bf/test/Verifier.test.ts#L114
		"segwit": {
			signedMessage: verifier.SignedMessage{
				Address:   "3HSVzEhCFuH9Z3wvoWTexy7BMVVp3PjS6f",
				Message:   "Hello World",
				Signature: "AkgwRQIhAMd2wZSY3x0V9Kr/NClochoTXcgDaGl3OObOR17yx3QQAiBVWxqNSS+CKen7bmJTG6YfJjsggQ4Fa2RHKgBKrdQQ+gEhAxa5UDdQCHSQHfKQv14ybcYm1C9y6b12xAuukWzSnS+w\n",
			},
			expectedError: "unsupported address type '*btcutil.AddressScriptHash'",
		},
		// Taken from https://github.com/ACken2/bip322-js/blob/159456f44f31f0b38097b957bbe75c0eae4971bf/test/Verifier.test.ts#L302
		"taproot - script-spend": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1p3r88nsysd8sv555nur4h85wdupa5z0xpcgcdjxy5up30re8gcneswrkwkv",
				Message:   "Hello World - This should fail",
				Signature: "A4AxODdkNTJkNGVkNDQ2OThlY2M5NjJlZDc0ZDdmODIyODIwNDc1YTc1NjdjMTViYmFkOGY5MWNlOTZkMGYxMzJkMmQxM2U0MzA3OWFlNzAwMTE5YzkxYTQ2MjA4Yzk5NWUzYTE4YjUzNjYzNjhkZDA0NDUwYzNmZjU2NTIyMWQyY+AyMDVkZTgxNTRlNzBkNmFmNTI5MDZhNGM0ZDc4OThiMDE4MGRlNWRiOGI3Y2Q0NGNiZDI3Y2RkZmY3NzUxY2ViYzdhYzAwNjMwMzZmNzI2NDAxMDExODc0NjU3ODc0MmY3MDZjNjE2OTZlM2I2MzY4NjE3MjczNjU3NDNkNzU3NDY2MmQzODAwMmE3YjIyNzAyMjNhMjI3MzZlNzMyMjJjMjI2ZjcwMjIzYTIyNzI2NTY3MjIyYzIyNmU2MTZkNjUyMjNhMjIzNjMzMzEzMjM4MmU3MzYxNzQ3MzIyN2Q2OEJjMDVkZTgxNTRlNzBkNmFmNTI5MDZhNGM0ZDc4OThiMDE4MGRlNWRiOGI3Y2Q0NGNiZDI3Y2RkZmY3NzUxY2ViYzc=",
			},
			expectedError: "script execution failed: control block proof is not a multiple of 32: 33",
		},
		// Taken from https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1765
		"taproot - wrong message": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3",
				Message:   "Hello World - This should fail",
				Signature: "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==",
			},
			expectedError: "script execution failed: ",
		},
		// Taken from https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1730
		"p2sh - 2-of-3 multisig": {
			signedMessage: verifier.SignedMessage{
				Address:   "3LnYoUkFrhyYP3V7rq3mhpwALz1XbCY9Uq",
				Message:   "This will be a p2sh 2-of-3 multisig BIP 322 signed message",
				Signature: "AAAAAAHNcfHaNfl8f/+ZC2gTr8aF+0KgppYjKM94egaNm/u1ZAAAAAD8AEcwRAIhAJ6hdj61vLDP+aFa30qUZQmrbBfE0kiOObYvt5nqPSxsAh9IrOKFwflfPRUcQ/5e0REkdFHVP2GGdUsMgDet+sNlAUcwRAIgH3eW/VyFDoXvCasd8qxgwj5NDVo0weXvM6qyGXLCR5YCIEwjbEV6fS6RWP6QsKOcMwvlGr1/SgdCC6pW4eH87/YgAUxpUiECKJfGy28imLcuAeNBLHCNv3NRP5jnJwFDNRXCYNY/vJ4hAv1RQtaZs7+vKqQeWl2rb/jd/gMxkEjUnjZdDGPDZkMLIQL65cH2X5O7LujjTLDL2l8Pxy0Y2UUR99u1qCfjdz7dklOuAAAAAAEAAAAAAAAAAAFqAAAAAA==",
			},
			expectedError: "unsupported address type '*btcutil.AddressScriptHash'",
		},
		// Taken from https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1743
		"p2wsh - 3-of-3 multisig": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1qlqtuzpmazp2xmcutlwv0qvggdvem8vahkc333usey4gskug8nutsz53msw",
				Message:   "This will be a p2wsh 3-of-3 multisig BIP 322 signed message",
				Signature: "BQBIMEUCIQDQoXvGKLH58exuujBOta+7+GN7vi0lKwiQxzBpuNuXuAIgIE0XYQlFDOfxbegGYYzlf+tqegleAKE6SXYIa1U+uCcBRzBEAiATegywVl6GWrG9jJuPpNwtgHKyVYCX2yfuSSDRFATAaQIgTLlU6reLQsSIrQSF21z3PtUO2yAUseUWGZqRUIE7VKoBSDBFAiEAgxtpidsU0Z4u/+5RB9cyeQtoCW5NcreLJmWXZ8kXCZMCIBR1sXoEinhZE4CF9P9STGIcMvCuZjY6F5F0XTVLj9SjAWlTIQP3dyWvTZjUENWJowMWBsQrrXCUs20Gu5YF79CG5Ga0XSEDwqI5GVBOuFkFzQOGH5eTExSAj2Z/LDV/hbcvAPQdlJMhA17FuuJd+4wGuj+ZbVxEsFapTKAOwyhfw9qpch52JKxbU64=",
			},
			expectedError: "unsupported address type '*btcutil.AddressWitnessScriptHash'",
		},
		"Pay-to-Witness-Script-Hash - P2WSH": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak",
				Message:   "doesn't matter",
				Signature: "ZG9lc24ndCBtYXR0ZXI=",
			},
			expectedError: "unsupported address type '*btcutil.AddressWitnessScriptHash'",
		},
	}

	for name, tt := range tests {
		s.Run(name, func() {
			// Decode the address
			address, err := btcutil.DecodeAddress(tt.signedMessage.Address, &chaincfg.MainNetParams)
			s.Require().NoError(err)

			// Decode the signature
			signatureDecoded, err := base64.StdEncoding.DecodeString(tt.signedMessage.Signature)
			s.Require().NoError(err)

			valid, err := bip322.Verify(address, tt.signedMessage.Message, signatureDecoded)
			s.Require().EqualError(err, tt.expectedError)
			s.False(valid)
		})
	}
}

func (s *VerifyTestSuite) TestVerify() {
	tests := map[string]verifier.SignedMessage{
		// BIP-322 test vector #0 - https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Test_vectors
		"test vector #0": {
			Address:   "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
			Message:   "Hello World",
			Signature: "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
		},
		// BIP-322 test vector #1 - https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Test_vectors
		"test vector #1": {
			Address:   "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
			Message:   "",
			Signature: "AkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
		},
		// bip-322 signature created using buidl-python library with same parameters as https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Test_vectors
		"buidl-python - test vector #0": {
			Address:   "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
			Message:   "Hello World",
			Signature: "AkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
		},
		// Generated via the Leather Wallet, using the same words as for unisat
		"leather - segwit native": {
			Address:   "bc1qvhnxd953tzt4kcqpcgk83wu2r9shf59q2t4egu",
			Message:   "hello",
			Signature: "AkgwRQIhAMPtK3P+dVOTFe5w9Rw2IJzjMjAXOXQUaBptg3QcT64JAiAX6TxbLPTetNJA7gKoARU/WH7Owm4YBS7ALeN+2LcBeQEhA59DAKSL/e9Zj9BEfm4DyBlGTAH9/8cYInHmMqbjz8EX",
		},
		// Generated via the Leather Wallet, using the same words as for unisat
		"leather - taproot": {
			Address:   "bc1pgc9k3vdmr9aecmwj09qg5qv550qyyrydufyfmxrsvk5474rxenuqrq4lcz",
			Message:   "hello",
			Signature: "AUBuPt7wX3zcAaMs7F/oGXPROspWWIvBh/GqjTQ6uPq8sUPxSIqGGaz8z4yuEoYRzXwaAeXBucxjlygiR02zvX2L",
		},
		// Single key taproot bip-322 signature (created with the buidl-python library)
		// Taken from: https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1754
		"buidl-python - taproot": {
			Address:   "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3",
			Message:   "Hello World",
			Signature: "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==",
		},
		// Single key taproot bip-322 signature (created with the sparrow)
		"sparrow - taproot": {
			Address:   "bc1pqqeyhah6g75dwr942xv40h255q4nshqw4k8ylyhe7plej2eg3mnqz9w4np",
			Message:   "Taproot, lets go!",
			Signature: "AUE8tKBiwiq64JYkSbf+4byheZlmDB5xyasRJ+ujM9/h/BfHFsd4jovtmmEfSsEZTBzoOP9m7We92UEbhqb4sBf4AQ==",
		},
		// Single key taproot bip-322 signature (created by nullish.org)
		"nullish.org - taproot": {
			Address:   "bc1pkr9m9rcspdyzhtf7g2pkc2l8ww7yp0prckkvg252edk7pvusx5ts3n5e0x",
			Message:   "nullish.org",
			Signature: "AUHyxHye4t2wc3zE/jj+S9itMJh1+XrqR7aaHtkoKsy/d49gzAJnstbZgdMYh6Ywn+g8tG9U9oqrMNqlVdM8I8R9AQ==",
		},
	}

	for name, tt := range tests {
		s.Run(name, func() {
			// Decode the address
			address, err := btcutil.DecodeAddress(tt.Address, &chaincfg.MainNetParams)
			s.Require().NoError(err)

			// Decode the signature
			signatureDecoded, err := base64.StdEncoding.DecodeString(tt.Signature)
			s.Require().NoError(err)

			valid, err := bip322.Verify(address, tt.Message, signatureDecoded)
			s.Require().NoError(err)
			s.True(valid)
		})
	}
}
