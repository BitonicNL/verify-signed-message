package signature_test

import (
	"math/big"
	"reflect"
	"testing"
	"unsafe"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/suite"

	"github.com/bitonicnl/verify-signed-message/internal"
	"github.com/bitonicnl/verify-signed-message/internal/generic/signature"
)

type SignatureTestSuite struct {
	suite.Suite

	signatureEncoded []uint8
	publicKeyEncoded []uint8
}

func (s *SignatureTestSuite) SetupTest() {
	// uint8 representation of `H/iew/NhHV9V9MdUEn/LFOftaTy1ivGPKPKyMlr8OSokNC755fAxpSThNRivwTNsyY9vPUDTRYBPc2cmGd5d4y4=`.
	s.signatureEncoded = []uint8{
		31, 248, 158, 195, 243, 97, 29, 95, 85, 244, 199, 84, 18, 127, 203, 20, 231, 237, 105, 60, 181,
		138, 241, 143, 40, 242, 178, 50, 90, 252, 57, 42, 36, 52, 46, 249, 229, 240, 49, 165, 36, 225, 53,
		24, 175, 193, 51, 108, 201, 143, 111, 61, 64, 211, 69, 128, 79, 115, 103, 38, 25, 222, 93, 227, 46,
	}

	// uint8 representation of the public key for `14dD6ygPi5WXdwwBTt1FBZK3aD8uDem1FY`.
	s.publicKeyEncoded = []uint8{
		3, 77, 160, 6, 249, 88, 190, 186, 120, 236, 84, 68, 61, 244, 163, 245, 34, 55, 37, 63,
		122, 232, 203, 219, 23, 220, 207, 63, 234, 165, 127, 49, 38,
	}
}

func TestServiceTestSuite(t *testing.T) {
	// Run everything in parallel
	t.Parallel()

	suite.Run(t, new(SignatureTestSuite))
}

func (s *SignatureTestSuite) TestParseCompactInvalid() {
	compactedSignature, err := signature.ParseCompact([]byte{})
	s.Require().EqualError(err, "invalid compact signature size")
	s.Require().Nil(compactedSignature)
}

func (s *SignatureTestSuite) TestParseCompactInvalidRecoveryCode() {
	compactedSignature, err := signature.ParseCompact([]byte{
		0x68, 0x1c, 0x6e, 0x8b, 0xac, 0xd1, 0x97, 0x25,
		0x18, 0x37, 0xcf, 0xe1, 0x7a, 0xa2, 0x07, 0x95,
		0x18, 0xd7, 0x1c, 0x3b, 0x68, 0x3b, 0x40, 0x20,
		0xf9, 0x3d, 0x64, 0x36, 0x2a, 0x0a, 0x63, 0x4e,
		0x17, 0x28, 0x2b, 0x47, 0x94, 0x16, 0x69, 0x6b,
		0xe2, 0x76, 0x7f, 0x02, 0xb2, 0x5e, 0xd1, 0x3c,
		0x43, 0x56, 0x4c, 0x28, 0xc3, 0x80, 0x5f, 0x6a,
		0x6a, 0x32, 0xe3, 0x0b, 0x6a, 0x26, 0xf0, 0x2f,
		0xc9,
	})
	s.Require().EqualError(err, "invalid compact signature recovery code")
	s.Require().Nil(compactedSignature)
}

func (s *SignatureTestSuite) TestParseCompact() {
	compactedSignature, err := signature.ParseCompact(s.signatureEncoded)
	s.Require().NoError(err)

	// Retrieve the unexported fields
	R := s.getFieldFromSignature(compactedSignature, "r")
	S := s.getFieldFromSignature(compactedSignature, "s")

	// Ensure they match what we defined
	s.Require().Equal("112454100686917088716763005039207074580155840372180209748670933598947425987108", R.String())
	s.Require().Equal("23603267825273168310009216611640910854054822424267934178492474518750065713966", S.String())
}

func (s *SignatureTestSuite) TestVerifyInvalidPublicKey() {
	err := signature.Verify(s.signatureEncoded, &btcec.PublicKey{}, []byte{})
	s.Require().EqualError(err, "public key was not correctly instantiated")
}

func (s *SignatureTestSuite) TestVerifyInvalidEncodedSignature() {
	key, err := btcec.NewPrivateKey()
	s.Require().NoError(err)

	err = signature.Verify([]byte{}, key.PubKey(), []byte{})
	s.Require().EqualError(err, "invalid compact signature size")
}

func (s *SignatureTestSuite) TestVerifyInvalidSignature() {
	key, err := btcec.NewPrivateKey()
	s.Require().NoError(err)

	err = signature.Verify(s.signatureEncoded, key.PubKey(), []byte{})
	s.Require().EqualError(err, "signature could not be verified")
}

func (s *SignatureTestSuite) TestVerifyInvalidMessage() {
	magicMessage := internal.CreateMagicMessage("INVALID")
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	publicKey, err := btcec.ParsePubKey(s.publicKeyEncoded)
	s.Require().NoError(err)

	s.Require().EqualError(signature.Verify(s.signatureEncoded, publicKey, messageHash), "signature could not be verified")
}

func (s *SignatureTestSuite) TestVerify() {
	magicMessage := internal.CreateMagicMessage("test message")
	messageHash := chainhash.DoubleHashB([]byte(magicMessage))

	publicKey, err := btcec.ParsePubKey(s.publicKeyEncoded)
	s.Require().NoError(err)

	s.Require().NoError(signature.Verify(s.signatureEncoded, publicKey, messageHash))
}

func (s *SignatureTestSuite) getFieldFromSignature(compactedSignature *ecdsa.Signature, field string) *big.Int {
	// Mark as helper
	s.T().Helper()

	// Reflect the signature struct
	elem := reflect.ValueOf(compactedSignature).Elem()

	// Grab the unexported field
	rReflected := elem.FieldByName(field)
	m, ok := reflect.NewAt(rReflected.Type(), unsafe.Pointer(rReflected.UnsafeAddr())).Elem().Interface().(btcec.ModNScalar)
	s.Require().True(ok)

	// Grab ModNScalar bytes
	bytes := m.Bytes()

	// Convert field back to big.Int
	return new(big.Int).SetBytes(bytes[:])
}
