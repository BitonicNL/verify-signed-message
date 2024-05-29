package verifier_test

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/suite"

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
		"address - invalid": {
			signedMessage: verifier.SignedMessage{
				Address:   "INVALID",
				Message:   "test message",
				Signature: "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
			},
			expectedError: "could not decode address: decoded address is of unknown format",
		},
		"address - wrong network": {
			signedMessage: verifier.SignedMessage{
				Address:   "tb1qnzwefk7wzphlc4xeawf8p4yqtcwzdgsvukwma8",
				Message:   "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.",
				Signature: "AUEUpr/X2GrTv1+LUytXEAv+FDADgWkFppbx87/xz8DNEVXSunSDo1/asR9DbeAVgK3Ao4B1cAxEz3pW7wEQGmLvAQ==",
			},
			expectedError: "address 'tb1qnzwefk7wzphlc4xeawf8p4yqtcwzdgsvukwma8' is not valid for network 'mainnet'",
		},
		"signature - invalid": {
			signedMessage: verifier.SignedMessage{
				Address:   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5",
				Message:   "test message",
				Signature: "INVALID",
			},
			expectedError: "could not decode signature: illegal base64 data at input byte 4",
		},
		// Incorrect signature that is valid, but cannot be recovered, taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/test/verifymessage.php#L100
		"signature - invalid curve": {
			signedMessage: verifier.SignedMessage{
				Address:   "1C9CRMGBYrGKKQ6eEpwm4dzMqkRZxPB5xa",
				Message:   "test",
				Signature: "IQt3ycjmA6LCbcTiFcj7o6odqX5PKeYPmL+dwcblLc/Xor1E2szTlEZKtHdzSrSz78PbYQUlX5a5VuDeSJLrEr0=",
			},
			expectedError: "could not recover pubkey: invalid signature: signature R + N >= P",
		},
		// Taken from https://github.com/luke-jr/bitcoin/blob/9ab7b8ada61a5f558c92c3eb9fd3cd3625d8cc09/src/test/util_tests.cpp#L1764
		"bip-322 - p2tr - wrong message": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3",
				Message:   "Hello World - This should fail",
				Signature: "AUHd69PrJQEv+oKTfZ8l+WROBHuy9HKrbFCJu7U1iK2iiEy1vMU5EfMtjc+VSHM7aU0SDbak5IUZRVno2P5mjSafAQ==",
			},
			expectedError: "script execution failed: ",
		},
	}

	for name, tt := range tests {
		s.Run(name, func() {
			valid, err := verifier.Verify(tt.signedMessage)
			s.False(valid)
			s.Require().EqualError(err, tt.expectedError)
		})
	}
}

func (s *VerifyTestSuite) TestVerifyWithChainTestnet() {
	tests := map[string]verifier.SignedMessage{
		"electrum - segwit native": {
			Address:   "tb1qr97cuq4kvq7plfetmxnl6kls46xaka78n2288z",
			Message:   "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.",
			Signature: "H/bSByRH7BW1YydfZlEx9x/nt4EAx/4A691CFlK1URbPEU5tJnTIu4emuzkgZFwC0ptvKuCnyBThnyLDCqPqT10=",
		},
		"sparrow - bip-322 - segwit native": {
			Address:   "tb1qnzwefk7wzphlc4xeawf8p4yqtcwzdgsvukwma8",
			Message:   "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.",
			Signature: "AkcwRAIgLvNWZneiHQUgulpYhIFarxws7a+k/QUTlbEFgdr2bOwCIG4Za9UKDJmc7V0eoyt/rCKe1wUr3F3WqHKeoSbMaFd6ASEDElXeZo3eLtCBIF2hvhxGdJzZonHbew9M1RXYsZZX+rg=",
		},
	}

	for name, tt := range tests {
		s.Run(name, func() {
			valid, err := verifier.VerifyWithChain(tt, &chaincfg.TestNet3Params)
			s.Require().NoError(err)
			s.True(valid)
		})
	}
}

func (s *VerifyTestSuite) TestVerify() {
	tests := map[string]verifier.SignedMessage{
		// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/tests/ecc/test_bms.py
		"generic - legacy - compressed": {
			Address:   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5",
			Message:   "test message",
			Signature: "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
		},
		// Based on the test above
		"generic - legacy - compressed - untrimmed": {
			Address:   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5",
			Message:   "  test message  ",
			Signature: "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
		},
		// BIP-322 test vector #0 - https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#user-content-Test_vectors
		"bip-322 - native segwit - test vector #0": {
			Address:   "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
			Message:   "Hello World",
			Signature: "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
		},
	}

	for i := range tests {
		s.Run(i, func() {
			valid, err := verifier.Verify(tests[i])
			s.Require().NoError(err)
			s.True(valid)
		})
	}
}
