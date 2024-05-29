package flags

// All returns every possible recovery flag, taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/btclib/ecc/bms.py#L83
func All() []int {
	return []int{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42}
}

// Compressed returns all compressed recovery flags.
func Compressed() []int {
	return []int{31, 32, 33, 34}
}

// ElectrumP2WPKH returns all P2WPKH recovery flags related to Electrum.
func ElectrumP2WPKH() []int {
	return []int{31, 32, 33, 34}
}

// ElectrumP2SHAndP2WPKH returns all P2SH-P2WPKH recovery flags related to Electrum.
func ElectrumP2SHAndP2WPKH() []int {
	return []int{31, 32, 33, 34}
}

// GetKeyID returns the Key ID for a specified recovery flag
// Taken from https://github.com/btclib-org/btclib/blob/v2023.7.12/btclib/ecc/bms.py#L302
func GetKeyID(recoveryFlag int) int {
	return (recoveryFlag - 27) & 0b11
}

// ShouldBeCompressed returns if a recovery flag signals a compressed key
// Taken from https://github.com/btclib-org/btclib/blob/v2023.7.12/btclib/ecc/bms.py#L305
func ShouldBeCompressed(recoveryFlag int) bool {
	return recoveryFlag > 30
}

// Trezor returns all recovery flags related to Trezor.
func Trezor() []int {
	return append(TrezorP2SHAndP2WPKH(), TrezorP2WPKH()...)
}

// TrezorP2WPKH returns all P2WPKH recovery flags related to Trezor.
func TrezorP2WPKH() []int {
	return []int{39, 40, 41, 42}
}

// TrezorP2SHAndP2WPKH returns all P2SH-P2WPKH recovery flags related to Trezor.
func TrezorP2SHAndP2WPKH() []int {
	return []int{35, 36, 37, 38}
}

// Uncompressed returns all uncompressed recovery flags.
func Uncompressed() []int {
	return []int{27, 28, 29, 30}
}
