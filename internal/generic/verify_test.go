package generic_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/suite"

	"github.com/bitonicnl/verify-signed-message/internal/generic"
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
		"address - different": {
			signedMessage: verifier.SignedMessage{
				Address:   "14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V",
				Message:   "test message",
				Signature: "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
			},
			expectedError: "generated address '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5' does not match expected address '14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V'",
		},
		// Checksum mismatch, taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/test/verifymessage.php#L32
		"message - different": {
			signedMessage: verifier.SignedMessage{
				Address:   "14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V",
				Message:   "Totally different message, thus different calculated address",
				Signature: "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
			},
			expectedError: "generated address '1LwzpMrpDakgZ9XPCsSuGG6ZXCE3fkNdQR' does not match expected address '14wPe34dikRzK4tMYvtwMMJCEZbJ7ar35V'",
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
		"signature - non-bitcoin": {
			signedMessage: verifier.SignedMessage{
				Address:   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5",
				Message:   "test message",
				Signature: "zPOBbkXzwDgGVU3Gxk0noVuLq8P1pGfQUxnS0nzuxEN3qR/U/s63P81io7LV04ZxN88gVX/Qw0rzLFBR8q4IkUc=",
			},
			expectedError: "invalid recovery flag: 204",
		},
		"signature - too short": {
			signedMessage: verifier.SignedMessage{
				Address:   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5",
				Message:   "test message",
				Signature: "VGhpcyBpcyBub3QgdmFsaWQ=",
			},
			expectedError: "wrong signature length: 17 instead of 65",
		},
		// Generated via https://demo.unisat.io/ and has an invalid recovery flag, which causes it to be generated uncompressed (the address is compressed).
		// 2024-03-23: This issue seems to have been resolved on their end.
		"unisat - P2PKH": {
			signedMessage: verifier.SignedMessage{
				Address:   "15tbg628HntFEB7xjyVrSo3ck5jbKuGhQD",
				Message:   "hello world",
				Signature: "G5WBoAY8ehQtP8UnS2boqjid2vYxH2/m69Il3T1SySRGVO2H1KIrTwVkPe2aU3BXyX/CYzBUaXYyWmC8vxXFIyw=",
			},
			expectedError: "generated address '1NAnF6TPUieShRuhVyK5nYAGpvGwXSS7RX' does not match expected address '15tbg628HntFEB7xjyVrSo3ck5jbKuGhQD'",
		},
		// Generated via https://demo.unisat.io/ and has an invalid recovery flag.
		// 2024-03-23: This issue seems to have been resolved on their end.
		"unisat - P2SH-P2WPKH": {
			signedMessage: verifier.SignedMessage{
				Address:   "32ypXz5xwzGLbEnfLJWw1VUKcLbvDDVTVV",
				Message:   "hello world",
				Signature: "HEZseoQ4aMFs8ERwwB9jm4qgoUH/sFRMTEADV9pr5EQadve7ebbsQ/LH/c7QpnDY/ygi24jlnPoZUcOT7Vo8vOw=",
			},
			expectedError: "cannot use P2SH for recovery flag 'P2PKH uncompressed'",
		},
		// Generated via https://demo.unisat.io/ and has an invalid recovery flag.
		// 2024-03-23: This issue seems to have been resolved on their end.
		"unisat - P2WPKH": {
			signedMessage: verifier.SignedMessage{
				Address:   "bc1qzex95t5x94sq70g8u7zyc5jcn6vv27swtm5uqs",
				Message:   "hello world",
				Signature: "HCxsLSgGi9RduaXTTzQvbpTNVR/KyWX9Rk4SU0LnhXN8T+A+8titHwMZea2PiOSQzfSu2J+og307rEw2GRZDeDE=",
			},
			expectedError: "cannot use P2WPKH for recovery flag 'P2PKH uncompressed'",
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

			valid, err := generic.Verify(address, tt.signedMessage.Message, signatureDecoded, &chaincfg.MainNetParams)
			s.Require().EqualError(err, tt.expectedError)
			s.False(valid)
		})
	}
}

func (s *VerifyTestSuite) TestVerify() {
	tests := map[string]verifier.SignedMessage{
		"bitcoin core - legacy": {
			Address:   "1CBHFokbnZVuq9fA3yjPTvSNXpdRRP7eUB",
			Message:   " Lorem ipsum dolor sit amet, consectetur adipiscing elit. In a turpis dignissim, tincidunt dolor quis, aliquam justo. Sed eleifend eleifend tempus. Sed blandit lectus at ullamcorper blandit. Quisque suscipit ligula lacus, tempor fringilla erat pharetra a. Curabitur pretium varius purus vel luctus. Donec fringilla velit vel risus fermentum, ac aliquam enim sollicitudin. Aliquam elementum, nunc nec malesuada fringilla, sem sem lacinia libero, id tempus nunc velit nec dui. Vestibulum gravida non tortor sit amet accumsan. Nunc semper vehicula vestibulum. Praesent at nibh dapibus, eleifend neque vitae, vehicula justo. Nam ultricies at orci vel laoreet. Morbi metus sapien, pulvinar ut dui ut, malesuada lobortis odio. Curabitur eget diam ligula. Nunc vel nisl consectetur, elementum magna et, elementum erat. Maecenas risus massa, mattis a sapien sed, molestie ullamcorper sapien. ",
			Signature: "H3HQ9gwAMCee0T7M8fZTgvIYlG6pMnpP41ioDUTKjlPsOMHwrF3qmgsM+kFoWLL1u6P4ZUf3nwYacPCeBjrzFzE=",
		},
		// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/tests/ecc/test_bms.py
		"bms compressed - legacy": {
			Address:   "14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY",
			Message:   "test message",
			Signature: "H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=",
		},
		// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/tests/ecc/test_bms.py
		"bms compressed p2pkh": {
			Address:   "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5",
			Message:   "test message",
			Signature: "IFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
		},
		// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/tests/ecc/test_bms.py
		"bms uncompressed - legacy": {
			Address:   "1HUBHMij46Hae75JPdWjeZ5Q7KaL7EFRSD",
			Message:   "test message",
			Signature: "G/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=",
		},
		// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/tests/ecc/test_bms.py
		"bms uncompressed p2pkh": {
			Address:   "19f7adDYqhHSJm2v7igFWZAqxXHj1vUa3T",
			Message:   "test message",
			Signature: "HFqUo4/sxBEFkfK8mZeeN56V13BqOc0D90oPBChF3gTqMXtNSCTN79UxC33kZ8Mi0cHy4zYCnQfCxTyLpMVXKeA=",
		},
		"coinomi - legacy": {
			Address:   "1PjSDaSiVdWW6YjwFA6FHwwfqkZdPEJUZv",
			Message:   "Test message!",
			Signature: "IK7I33rASHdSeYDotQ9WfO4jrxgdl5ef/bTbX6Q5PNtFY9rJeAHfoZV5GpDO1K3OqoPs8ROZRXPyMNLkVOxJ+Rc=",
		},
		"coinomi - segwit": {
			Address:   "39FT3L2wH56h2jmae5abPU1A7nVs6QyApV",
			Message:   "Test message!",
			Signature: "HzpoLFjr+eUPkseb+i0Vaqj7FRm5o1+Ei/kae7XWN6nmFLmvLi7uWicerYNXjCMUf3nCnm/9UPb6SYJLI60Nh8A=",
		},
		"coinomi - segwit native": {
			Address:   "bc1q0utxws6ptfdfcvaz29y4st065t5ku6vcqd364f",
			Message:   "Test message!",
			Signature: "H+G7Fz3EVxX02kIker4HPgnP8Mlf3bT52p81hnNAahTOGJ8ANSaU0bF5RsprgTH6LXLx/PmCka48Ov7OrPw2bms=",
		},
		"electrum - legacy": {
			Address:   "1CPBDkm8ER3o7r2HANcvNoVHsBYKcUHTp9",
			Message:   "Integer can be encoded depending on the represented value to save space. Variable length integers always precede an array/vector of a type of data that may vary in length. Longer numbers are encoded in little endian. If you're reading the Satoshi client code (BitcoinQT) it refers to this encoding as a \"CompactSize\". Modern Bitcoin Core also has the VARINT macro which implements an even more compact integer for the purpose of local storage (which is incompatible with \"CompactSize\" described here). VARINT is not a part of the protocol.",
			Signature: "IHTr8YSzZ17Ut/Qaaui6BvGd42+TGwVwNYaIMUAZQTZRSqDtaTfsOcaOllPstp3IxzMlpXVOzLxNZE8r8ieffnY=",
		},
		"electrum - segwit native": {
			Address:   "bc1qsdjne3y6ljndzvg9z9qrhje8k7p2m5yas704hn",
			Message:   "Integer can be encoded depending on the represented value to save space. Variable length integers always precede an array/vector of a type of data that may vary in length. Longer numbers are encoded in little endian. If you're reading the Satoshi client code (BitcoinQT) it refers to this encoding as a \"CompactSize\". Modern Bitcoin Core also has the VARINT macro which implements an even more compact integer for the purpose of local storage (which is incompatible with \"CompactSize\" described here). VARINT is not a part of the protocol.",
			Signature: "H3TkHAXCKRfyDowCra5YRDF/Vkk2HQCel/pgEgTj9LYaWpnviSRcuYtv/CZk7NTyHsJnYP56bqbvuU3PejwLCnA=",
		},
		"mycelium - legacy": {
			Address:   "13VwTBVLNpNSQVTrYpuHQVJYnk2y2Nr1ue",
			Message:   "Test message!",
			Signature: "Hxpnr2oDFTjivFkrrp89UoMrzaAzFkkEciS3MUHCfdoEXN/KvHi9ii2Xz+FuQ6KjlZDlaPb197E8TWnhIAzbT0M=",
		},
		"mycelium - segwit": {
			Address:   "325ZMWMu9vaWQeUG8Gc8MzsVKzt3Rqn8H7",
			Message:   "Test message!",
			Signature: "IM/bkqpERGRFDGgxnceinULcqz1iRVBSUVlnDPZRKHGUQMC5t1P5wRp2/1b1+rpjFHhSS2pExB88cA750PNRlaw=",
		},
		"mycelium - segwit native": {
			Address:   "bc1q58dh2fpwms37g29nw979pa65lsvjkqxq82jzvv",
			Message:   "Test message!",
			Signature: "ILNax/LC+m3WwzIhnrieNN8DRzWTAgcVStSJmwdabUQII2fIlYUlEgnlNf4j2G4yJQoO4zFqCwaLOX4PDj1XwjA=",
		},
		// Taken from https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/tests/test_signmessage.py
		"python-bitcoinlib - legacy": {
			Address:   "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G",
			Message:   "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G",
			Signature: "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4=",
		},
		// Dumped from (changed TestNet to MainNet): https://github.com/Samourai-Wallet/ExtLibJ/blob/develop/src/test/java/com/samourai/wallet/util/MessageSignUtilGenericTest.java
		"samourai - legacy": {
			Address:   "1JSjyW3dZSQHv6jb6u6baXLUZnsThqmzf4",
			Message:   "hello foo",
			Signature: "INAP+PMyI2vqIxiEKIcPOaaffspU3gAPm0YWhCxJr5iqWbQwqns9+RiXIzuU9JoNQs/MQ1BZ4O2XM23utyw3jr0=",
		},
		// Dumped from (changed TestNet to MainNet): https://github.com/Samourai-Wallet/ExtLibJ/blob/develop/src/test/java/com/samourai/wallet/util/MessageSignUtilGenericTest.java
		"samourai - segwit native": {
			Address:   "bc1qnxhkjd3kcjdzqz4u0m47xj3dne907cd8yg7qdr",
			Message:   "hello foo",
			Signature: "IJruGdQX+V6s+zvzTD3msz2l1obPchx19/bsefr+QGihcRArLSzXtkoUXA8k0NkBsIpFXGRxbG/s+eimZ+eGg70=",
		},
		// Taken from https://github.com/trezor/trezor-firmware/blob/core/v2.3.4/tests/device_tests/test_msg_signmessage.py
		"trezor - legacy": {
			Address:   "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL",
			Message:   "This is an example of a signed message.",
			Signature: "IP2PL321I4/N0HfVIEw+aUnCYdcAJpzvwdnS3O9rlQI2MO5hf2yKz560DI7dcEycp06kr8OT9D81tOiVgyTL3Rw=",
		},
		// Taken from https://github.com/trezor/trezor-firmware/blob/core/v2.3.4/tests/device_tests/test_msg_signmessage.py
		"trezor - legacy - long message": {
			Address:   "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL",
			Message:   strings.Repeat("VeryLongMessage!", 64),
			Signature: "IApGR2zrhNBu9XhIKAJvkiyIFfV6rIN7jAEwB8qKhGDbY++Rfb6669EIscgUu+6m2x8rIkGpWOU/5xXMhrGZ2cM=",
		},
		// Taken from https://github.com/trezor/trezor-firmware/blob/core/v2.3.4/tests/device_tests/test_msg_signmessage.py
		"trezor - segwit native": {
			Address:   "bc1qannfxke2tfd4l7vhepehpvt05y83v3qsf6nfkk",
			Message:   "This is an example of a signed message.",
			Signature: "KLVddgDZ6afipJFV3fPP2455bCB/qrgzAQ+kH7eCiIm8R89iNIp6qgkjwIMqWJ+rVB6PEutU+3EckOIwfw9msZQ=",
		},
		// Taken from https://github.com/trezor/trezor-firmware/blob/core/v2.3.4/tests/device_tests/test_msg_signmessage.py
		"trezor - segwit native long message": {
			Address:   "bc1qannfxke2tfd4l7vhepehpvt05y83v3qsf6nfkk",
			Message:   strings.Repeat("VeryLongMessage!", 64),
			Signature: "KMb4biVeqnaMRH1jXZHaAWMaxUryI8LBgtT6NnbP7K5KGZrTOnT+BPtGw5QyrLjYPedNqQ9fARI7O32LwlK8f3E=",
		},
		// Taken from https://github.com/trezor/trezor-firmware/blob/core/v2.3.4/tests/device_tests/test_msg_signmessage.py
		"trezor - segwit - #0": {
			Address:   "3L6TyTisPBmrDAj6RoKmDzNnj4eQi54gD2",
			Message:   "This is an example of a signed message.",
			Signature: "I3RN5FFvrFwUCAgBVmRRajL+rZTeiXdc7H4k28JP4TMHWsCTAcTMjhl76ktkgWYdW46b8Z2Le4o4Ls21PC7gdQ0=",
		},
		// Taken from https://github.com/bitcoinjs/bitcoinjs-message/issues/20
		"trezor - segwit - #1": {
			Address:   "3LbZqMMHu371r5Fjve9qNhSQzuNi7EzqUR",
			Message:   "test123",
			Signature: "I2ehXowFWMZohHrJN+1IRdDwqN/UILqVmhIOHpeBdS4BYDCQpfDL1tTH7mNg6eeypno+Is8ApgWinkPnnz1NEq8=",
		},
		// Taken from https://github.com/trezor/trezor-firmware/blob/core/v2.3.4/tests/device_tests/test_msg_signmessage.py
		"trezor - segwit - long message": {
			Address:   "3L6TyTisPBmrDAj6RoKmDzNnj4eQi54gD2",
			Message:   strings.Repeat("VeryLongMessage!", 64),
			Signature: "I26t7jgGhPcHScUhQciqfDtq/YTQ5fOM+nGCPzsRBaXzTiODSlu28jn/KK2H9An0TkzmJpdUrcADiLGVB6XZOG8=",
		},
		// Taken from https://github.com/bitcoinjs/bitcoinjs-message/issues/20
		"electrum - segwit": {
			Address:   "3LbZqMMHu371r5Fjve9qNhSQzuNi7EzqUR",
			Message:   "test123",
			Signature: "H2ehXowFWMZohHrJN+1IRdDwqN/UILqVmhIOHpeBdS4BYDCQpfDL1tTH7mNg6eeypno+Is8ApgWinkPnnz1NEq8=",
		},
		"electrum - legacy - short message - uncompressed": {
			Address:   "18J72YSM9pKLvyXX1XAjFXA98zeEvxBYmw",
			Message:   "Test123",
			Signature: "Gzhfsw0ItSrrTCChykFhPujeTyAcvVxiXwywxpHmkwFiKuUR2ETbaoFcocmcSshrtdIjfm8oXlJoTOLosZp3Yc8=",
		},
		"electrum - legacy - long message - uncompressed": {
			Address:   "18J72YSM9pKLvyXX1XAjFXA98zeEvxBYmw",
			Message:   "Lorem ipsum dolor sit amet, consectetur adipiscing elit. In a turpis dignissim, tincidunt dolor quis, aliquam justo. Sed eleifend eleifend tempus. Sed blandit lectus at ullamcorper blandit. Quisque suscipit ligula lacus, tempor fringilla erat pharetra a. Curabitur pretium varius purus vel luctus. Donec fringilla velit vel risus fermentum, ac aliquam enim sollicitudin. Aliquam elementum, nunc nec malesuada fringilla, sem sem lacinia libero, id tempus nunc velit nec dui. Vestibulum gravida non tortor sit amet accumsan. Nunc semper vehicula vestibulum. Praesent at nibh dapibus, eleifend neque vitae, vehicula justo. Nam ultricies at orci vel laoreet. Morbi metus sapien, pulvinar ut dui ut, malesuada lobortis odio. Curabitur eget diam ligula. Nunc vel nisl consectetur, elementum magna et, elementum erat. Maecenas risus massa, mattis a sapien sed, molestie ullamcorper sapien.",
			Signature: "HHOGSz6AUEEyVGoCUw1GqQ5qy9KvW5uO1FfqWLbwYxkQVsI+sbM0jpBQWkyjr72166yiL/LQEtW3SpVBR1gXdYY=",
		},
		// Generated via https://demo.unisat.io/
		"unisat - legacy": {
			Address:   "19892aZkySq8Va3Qp2gk9dapNtWypnL1ek",
			Message:   "hello world~",
			Signature: "IOmbxBO4Wwy42+Q9JoOB2ZaXygdDCIaGKloc5igs+ZF0WqWIVDiFLmuUZKdGeSiz+VNPd19d4hPHgOXCfZfZveQ=",
		},
		// Generated via https://demo.unisat.io/
		"unisat - nested segwit": {
			Address:   "3MqrCDcTK16rkLEbu9Wfojdf7jbUMAJBRW",
			Message:   "hello world~",
			Signature: "IGCFq01RhaGbMOOuPWFn5H/ZCKx+P4srkb7O3BRS7mcISazqQbS9QThf3gSmH1Vrq/RLL+1pZQZISWe/XRIr1O0=",
		},
		// Generated via https://demo.unisat.io/
		"unisat - segwit native": {
			Address:   "bc1qvhnxd953tzt4kcqpcgk83wu2r9shf59q2t4egu",
			Message:   "hello world",
			Signature: "INuYn+2RZPLOzOXBYffJeMSVKRwIf+XaD3SrQa+WTO/aaKR/+JzS0zJplnc3H7dN8Da3bxvrQx3rPL/MCwZ5z7s=",
		},
		// Generated via https://demo.unisat.io/
		"unisat - taproot": {
			Address:   "bc1pgc9k3vdmr9aecmwj09qg5qv550qyyrydufyfmxrsvk5474rxenuqrq4lcz",
			Message:   "hello world",
			Signature: "H/KLWcCfl/P34V9TdPzcSlG3sdhllArBXjypbz9BBY1GXDRCwYogO50Crznm8I9P/JAfhnojgbV5vPYSAhWA1p0=",
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

			valid, err := generic.Verify(address, tt.Message, signatureDecoded, &chaincfg.MainNetParams)
			s.Require().NoError(err)
			s.True(valid)
		})
	}
}
