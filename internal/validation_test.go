package internal_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/bitonicnl/verify-signed-message/internal"
)

// Hash for 1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5, used in this test.
var pubKeyHash = []uint8{133, 113, 93, 2, 177, 222, 121, 165, 69, 34, 61, 182, 122, 239, 165, 136, 229, 124, 167, 194}

type ValidateTestSuite struct {
	suite.Suite
}

func TestValidateTestSuite(t *testing.T) {
	// Run everything in parallel
	t.Parallel()

	suite.Run(t, new(ValidateTestSuite))
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
			name: "Invalid recovery flag - TrezorP2WPKHAndP2SH",
			args: args{recoveryFlag: 35, pubKeyHash: []uint8{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2PKH for recovery flag 'BIP137 (Trezor) P2WPKH-P2SH'"),
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
			args: args{recoveryFlag: 32, pubKeyHash: pubKeyHash, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address '1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2PKH",
			args: args{recoveryFlag: 32, pubKeyHash: pubKeyHash, addr: &RandomAddress{Address: "1DAag8qiPLHh6hMFVu9qJQm9ro1HtwuyK5"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := internal.ValidateP2PKH(tt.args.recoveryFlag, tt.args.pubKeyHash, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, err, tt.want)
		})
	}
}

func (s *ValidateTestSuite) TestValidateP2SH() {
	pubKeyHashTooLong := make([]uint8, txscript.MaxScriptSize+2)
	_, err := rand.Read(pubKeyHashTooLong)
	require.NoError(s.T(), err)

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
			args: args{recoveryFlag: 35, pubKeyHash: pubKeyHash, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address '3Nxee1CFDqFRtUrixREpNMhsmH9TBXcY48' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2SH",
			args: args{recoveryFlag: 35, pubKeyHash: pubKeyHash, addr: &RandomAddress{Address: "3Nxee1CFDqFRtUrixREpNMhsmH9TBXcY48"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := internal.ValidateP2SH(tt.args.recoveryFlag, tt.args.pubKeyHash, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, err, tt.want)
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
			args: args{recoveryFlag: 32, witnessProg: pubKeyHash, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address 'bc1qs4c46q43meu623fz8km84ma93rjhef7z88rg99' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2WPKH",
			args: args{recoveryFlag: 32, witnessProg: pubKeyHash, addr: &RandomAddress{Address: "bc1qs4c46q43meu623fz8km84ma93rjhef7z88rg99"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := internal.ValidateP2WPKH(tt.args.recoveryFlag, tt.args.witnessProg, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, err, tt.want)
		})
	}
}

func (s *ValidateTestSuite) TestValidateP2TR() {
	// Generated via https://unisat.io/ which uses https://github.com/bitpay/bitcore
	x, y := &btcec.FieldVal{}, &btcec.FieldVal{}
	x.SetBytes(&[32]byte{199, 142, 160, 82, 151, 162, 66, 186, 11, 43, 16, 91, 237, 71, 91, 135, 150, 252, 234, 48, 99, 136, 19, 243, 89, 137, 196, 224, 241, 223, 158, 246})
	y.SetBytes(&[32]byte{72, 92, 183, 101, 120, 192, 238, 204, 246, 77, 101, 137, 220, 171, 222, 21, 13, 79, 125, 140, 76, 22, 138, 145, 121, 157, 206, 101, 219, 101, 217, 105})

	pubKey := btcec.NewPublicKey(x, y)

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
			name: "Invalid recovery flag - compressed",
			args: args{recoveryFlag: 33, pubKey: &btcec.PublicKey{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2TR for recovery flag 'compressed'"),
		},
		{
			name: "Invalid recovery flag - TrezorP2WPKH",
			args: args{recoveryFlag: 36, pubKey: &btcec.PublicKey{}, addr: &RandomAddress{}},
			want: errors.New("cannot use P2TR for recovery flag 'BIP137 (Trezor) P2WPKH-P2SH'"),
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
			name: "Invalid address for public key",
			args: args{recoveryFlag: 27, pubKey: pubKey, addr: &RandomAddress{Address: "Invalid"}},
			want: errors.New("generated address 'bc1pg48rw0vphy9mght5dr8s5prx92a44wpqmzk67xk8yjf5zlancj9sa3plhc' does not match expected address 'Invalid'"),
		},
		{
			name: "Valid P2TR",
			args: args{recoveryFlag: 27, pubKey: pubKey, addr: &RandomAddress{Address: "bc1pg48rw0vphy9mght5dr8s5prx92a44wpqmzk67xk8yjf5zlancj9sa3plhc"}},
			want: nil,
		},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			_, err := internal.ValidateP2TR(tt.args.recoveryFlag, tt.args.pubKey, tt.args.addr, &chaincfg.MainNetParams)
			require.Equal(t, err, tt.want)
		})
	}
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
