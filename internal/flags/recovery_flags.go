package flags

// Returns every possible recovery flag, taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/btclib/ecc/bms.py#L82
func All() []int {
	return []int{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42}
}

// Returns all compressed recovery flags.
func Compressed() []int {
	return []int{31, 32, 33, 34}
}

// Returns all P2WPKH recovery flags related to Electrum.
func ElectrumP2WPKH() []int {
	return []int{31, 32, 33, 34}
}

// Returns all P2WPKH-P2SH recovery flags related to Electrum.
func ElectrumP2WPKHAndP2SH() []int {
	return []int{31, 32, 33, 34}
}

// Returns the Key ID for a specified recovery flag
// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/btclib/ecc/bms.py#L311
func GetKeyID(recoveryFlag int) int {
	return (recoveryFlag - 27) & 0b11
}

// Returns if a recovery flag signals a compressed key
// Taken from https://github.com/btclib-org/btclib/blob/v2022.7.20/btclib/ecc/bms.py#L314
func ShouldBeCompressed(recoveryFlag int) bool {
	return recoveryFlag >= 31
}

// Returns all recovery flags related to Trezor.
func Trezor() []int {
	return append(TrezorP2WPKHAndP2SH(), TrezorP2WPKH()...)
}

// Returns all P2WPKH recovery flags related to Trezor.
func TrezorP2WPKH() []int {
	return []int{39, 40, 41, 42}
}

// Returns all P2WPKH-P2SH recovery flags related to Trezor.
func TrezorP2WPKHAndP2SH() []int {
	return []int{35, 36, 37, 38}
}

// Returns all uncompressed recovery flags.
func Uncompressed() []int {
	return []int{27, 28, 29, 30}
}
