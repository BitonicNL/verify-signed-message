package generic_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/bitonicnl/verify-signed-message/internal/generic"
)

type ValidateTestSuite struct {
	suite.Suite

	legacyPubKeyHash      []uint8
	compressedPublicKey   *btcec.PublicKey
	uncompressedPublicKey *btcec.PublicKey
}

func TestValidateTestSuite(t *testing.T) {
	// Run everything in parallel
	t.Parallel()

	suite.Run(t, new(ValidateTestSuite))
}

func (s *ValidateTestSuite) SetupTest() {
	// Compressed legacy public key in bytes (1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5)
	s.legacyPubKeyHash = []uint8{133, 113, 93, 2, 177, 222, 121, 165, 69, 34, 61, 182, 122, 239, 165, 136, 229, 124, 167, 194}

	// Compressed taproot public key in hexadecimal format (bc1pgc9k3vdmr9aecmwj09qg5qv550qyyrydufyfmxrsvk5474rxenuqrq4lcz)
	s.compressedPublicKey = s.createTaprootPublicKey("0296f45e80c8efdb88b544afde38f2a19d65d40086cff9e2fdd5868d5eb57ca8a6")

	// Uncompressed taproot public key in hexadecimal format (bc1pg48rw0vphy9mght5dr8s5prx92a44wpqmzk67xk8yjf5zlancj9sa3plhc)
	s.uncompressedPublicKey = s.createTaprootPublicKey("04c78ea05297a242ba0b2b105bed475b8796fcea30638813f35989c4e0f1df9ef6")
}

func (s *ValidateTestSuite) TestValidateP2PKH() {
	type args struct {
		recoveryFlag int
		pubKeyHash   []byte
		addr         btcutil.Address
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{
			name: "Invalid recovery flag - TrezorP2SHAndP2WPKH",
			args: args{recoveryFlag: 35, pubKeyHash: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2PKH for recovery flag 'BIP137 (Trezor) P2SH-P2WPKH'"),
		},
		{
			name: "Invalid recovery flag - TrezorP2WPKH",
			args: args{recoveryFlag: 39, pubKeyHash: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2PKH for recovery flag 'BIP137 (Trezor) P2WPKH'"),
		},
		{
			name: "Invalid PubKeyHash",
			args: args{recoveryFlag: 32, pubKeyHash: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("pkHash must be 20 bytes"),
		},
		{
			name: "Invalid address for public key hash",
			args: args{recoveryFlag: 32, pubKeyHash: s.legacyPubKeyHash, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2PKH",
			args: args{recoveryFlag: 32, pubKeyHash: s.legacyPubKeyHash, addr: &RandomAddress{Address: "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := generic.ValidateP2PKH(tt.args.recoveryFlag, tt.args.pubKeyHash, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, tt.want, err)
		})
	}
}

func (s *ValidateTestSuite) TestValidateP2SH() {
	pubKeyHashTooLong := make([]uint8, txscript.MaxScriptSize+2)
	_, err := rand.Read(pubKeyHashTooLong)
	s.Require().NoError(err)

	type args struct {
		recoveryFlag int
		pubKeyHash   []byte
		addr         btcutil.Address
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{
			name: "Invalid recovery flag - Uncompressed",
			args: args{recoveryFlag: 27, pubKeyHash: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2SH for recovery flag 'P2PKH uncompressed'"),
		},
		{
			name: "Invalid recovery flag - TrezorP2WPKH",
			args: args{recoveryFlag: 39, pubKeyHash: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2SH for recovery flag 'BIP137 (Trezor) P2WPKH'"),
		},
		{
			name: "Invalid pubKeyHash - Too long",
			args: args{recoveryFlag: 35, pubKeyHash: pubKeyHashTooLong, addr: &RandomAddress{Address: "Invalid"}},
			want: txscript.ErrScriptNotCanonical("adding 10005 bytes of data would exceed the maximum allowed canonical script length of 10000"),
		},
		{
			name: "Invalid address for public key hash",
			args: args{recoveryFlag: 35, pubKeyHash: s.legacyPubKeyHash, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address '3Nxee1CFDqFRtUrixREpNMhsmH9TBXcY48' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2SH",
			args: args{recoveryFlag: 35, pubKeyHash: s.legacyPubKeyHash, addr: &RandomAddress{Address: "3Nxee1CFDqFRtUrixREpNMhsmH9TBXcY48"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := generic.ValidateP2SH(tt.args.recoveryFlag, tt.args.pubKeyHash, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, tt.want, err)
		})
	}
}

func (s *ValidateTestSuite) TestValidateP2WPKH() {
	type args struct {
		recoveryFlag int
		witnessProg  []byte
		addr         btcutil.Address
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{
			name: "Invalid recovery flag - Uncompressed",
			args: args{recoveryFlag: 27, witnessProg: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2WPKH for recovery flag 'P2PKH uncompressed'"),
		},
		{
			name: "Invalid witness program",
			args: args{recoveryFlag: 32, witnessProg: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("witness program must be 20 bytes for p2wpkh"),
		},
		{
			name: "Invalid address for public key hash",
			args: args{recoveryFlag: 32, witnessProg: s.legacyPubKeyHash, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address 'bc1qs4c46q43meu623fz8km84ma93rjhef7z88rg99' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2WPKH",
			args: args{recoveryFlag: 32, witnessProg: s.legacyPubKeyHash, addr: &RandomAddress{Address: "bc1qs4c46q43meu623fz8km84ma93rjhef7z88rg99"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := generic.ValidateP2WPKH(tt.args.recoveryFlag, tt.args.witnessProg, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, tt.want, err)
		})
	}
}

// All addresses were generated via https://demo.unisat.io/
func (s *ValidateTestSuite) TestValidateP2TR() {
	type args struct {
		recoveryFlag int
		pubKey       *btcec.PublicKey
		addr         btcutil.Address
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{
			name: "Invalid recovery flag - TrezorP2WPKH",
			args: args{recoveryFlag: 36, pubKey: &btcec.PublicKey{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2TR for recovery flag 'BIP137 (Trezor) P2SH-P2WPKH'"),
		},
		{
			name: "Invalid recovery flag - TrezorP2WPKH",
			args: args{recoveryFlag: 39, pubKey: &btcec.PublicKey{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2TR for recovery flag 'BIP137 (Trezor) P2WPKH'"),
		},
		{
			name: "Invalid public key",
			args: args{recoveryFlag: 27, pubKey: btcec.NewPublicKey(&btcec.FieldVal{}, &btcec.FieldVal{}), addr: &RandomAddress{}},
			want: secp256k1.Error{Err: secp256k1.ErrPubKeyNotOnCurve, Description: "invalid public key: x coordinate 0000000000000000000000000000000000000000000000000000000000000000 is not on the secp256k1 curve"},
		},
		{
			name: "Invalid address for public key - compressed",
			args: args{recoveryFlag: 31, pubKey: s.compressedPublicKey, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address 'bc1pgc9k3vdmr9aecmwj09qg5qv550qyyrydufyfmxrsvk5474rxenuqrq4lcz' does not match expected address 'Invalid'"),
		},
		{
			name: "Invalid address for public key",
			args: args{recoveryFlag: 27, pubKey: s.uncompressedPublicKey, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address 'bc1pg48rw0vphy9mght5dr8s5prx92a44wpqmzk67xk8yjf5zlancj9sa3plhc' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2TR - compressed",
			args: args{recoveryFlag: 31, pubKey: s.compressedPublicKey, addr: &RandomAddress{Address: "bc1pgc9k3vdmr9aecmwj09qg5qv550qyyrydufyfmxrsvk5474rxenuqrq4lcz"}},
			want: nil,
		},
		{
			name: "Valid P2TR",
			args: args{recoveryFlag: 27, pubKey: s.uncompressedPublicKey, addr: &RandomAddress{Address: "bc1pg48rw0vphy9mght5dr8s5prx92a44wpqmzk67xk8yjf5zlancj9sa3plhc"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := generic.ValidateP2TR(tt.args.recoveryFlag, tt.args.pubKey, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, tt.want, err)
		})
	}
}

func (s *ValidateTestSuite) createTaprootPublicKey(publicKey string) *btcec.PublicKey {
	// Convert hexadecimal to bytes
	compressedPublicKeyBytes, err := hex.DecodeString(publicKey[2:])
	if err != nil {
		s.Require().NoError(err)
	}

	// Setup X,Y storage
	x, y := &btcec.FieldVal{}, &btcec.FieldVal{}

	// Since taproot uses x-only public keys, only set X
	x.SetBytes((*[32]byte)(compressedPublicKeyBytes[:32]))

	// Create a btcd public key
	return btcec.NewPublicKey(x, y)
}

// RandomAddress implements the btcutil.Address interface and serves as a no-op to test these calls.
type RandomAddress struct {
	Address string
}

func (b *RandomAddress) EncodeAddress() string {
	return b.Address
}

func (b *RandomAddress) ScriptAddress() []byte {
	return nil
}

func (b *RandomAddress) IsForNet(_ *chaincfg.Params) bool {
	return true
}

func (b *RandomAddress) String() string {
	return b.Address
}
