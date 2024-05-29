package flags_test

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/bitonicnl/verify-signed-message/internal/generic/flags"
)

type RecoveryFlagTestSuite struct {
	suite.Suite
}

func TestRecoveryFlagTestSuite(t *testing.T) {
	// Run everything in parallel
	t.Parallel()

	suite.Run(t, new(RecoveryFlagTestSuite))
}

func (s *RecoveryFlagTestSuite) TestAll() {
	s.Equal([]int{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42}, flags.All())
}

func (s *RecoveryFlagTestSuite) TestCompressed() {
	s.Equal([]int{31, 32, 33, 34}, flags.Compressed())
}

func (s *RecoveryFlagTestSuite) TestElectrumP2WPKH() {
	s.Equal([]int{31, 32, 33, 34}, flags.ElectrumP2WPKH())
}

func (s *RecoveryFlagTestSuite) TestElectrumP2SHAndP2WPKH() {
	s.Equal([]int{31, 32, 33, 34}, flags.ElectrumP2SHAndP2WPKH())
}

func (s *RecoveryFlagTestSuite) TestGetKeyID() {
	tests := []struct {
		name          string
		recoveryFlag  int
		expectedKeyID int
	}{
		{name: "30", recoveryFlag: 30, expectedKeyID: 3},
		{name: "31", recoveryFlag: 31, expectedKeyID: 0},
		{name: "32", recoveryFlag: 32, expectedKeyID: 1},
		{name: "33", recoveryFlag: 33, expectedKeyID: 2},
		{name: "34", recoveryFlag: 34, expectedKeyID: 3},
		{name: "35", recoveryFlag: 35, expectedKeyID: 0},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if got := flags.GetKeyID(tt.recoveryFlag); got != tt.expectedKeyID {
				t.Errorf("GetKeyID() = %v, want %v", got, tt.expectedKeyID)
			}
		})
	}
}

func (s *RecoveryFlagTestSuite) TestShouldBeCompressed() {
	tests := []struct {
		name         string
		recoveryFlag int
		expected     bool
	}{
		{name: "30", recoveryFlag: 30, expected: false},
		{name: "31", recoveryFlag: 31, expected: true},
		{name: "32", recoveryFlag: 32, expected: true},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			if got := flags.ShouldBeCompressed(tt.recoveryFlag); got != tt.expected {
				t.Errorf("ShouldBeCompressed() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func (s *RecoveryFlagTestSuite) TestTrezor() {
	s.Equal([]int{35, 36, 37, 38, 39, 40, 41, 42}, flags.Trezor())
}

func (s *RecoveryFlagTestSuite) TestTrezorP2WPKH() {
	s.Equal([]int{39, 40, 41, 42}, flags.TrezorP2WPKH())
}

func (s *RecoveryFlagTestSuite) TestTrezorP2SHAndP2WPKH() {
	s.Equal([]int{35, 36, 37, 38}, flags.TrezorP2SHAndP2WPKH())
}

func (s *RecoveryFlagTestSuite) TestUncompressed() {
	s.Equal([]int{27, 28, 29, 30}, flags.Uncompressed())
}
