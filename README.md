# Bitcoin Signed Message Verifier

[![Latest tag](https://img.shields.io/github/tag/bitonicnl/verify-signed-message.svg)](https://github.com/bitonicnl/verify-signed-message/tags)
![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.24-%23007d9c)
[![GoDoc](https://godoc.org/github.com/bitonicnl/verify-signed-message?status.svg)](https://pkg.go.dev/github.com/bitonicnl/verify-signed-message)
[![Tests status](https://github.com/bitonicnl/verify-signed-message/actions/workflows/test.yml/badge.svg)](https://github.com/BitonicNL/verify-signed-message/actions/workflows/test.yml)
[![Go report](https://goreportcard.com/badge/github.com/bitonicnl/verify-signed-message)](https://goreportcard.com/report/github.com/bitonicnl/verify-signed-message)
[![License](https://img.shields.io/github/license/bitonicnl/verify-signed-message)](./LICENSE)

> A simple Golang package with a single purpose, to verify messages signed via Bitcoin message signing (BMS).

## Requirements

- Golang 1.24+

## Installation

Your `$PATH` must contain the Go path and the Go `bin` path (see [GoLang's getting started](https://golang.org/doc/install#install) for more information). 

Once done, you can install this package: 
```bash
go get -u github.com/bitonicnl/verify-signed-message
```

## Usage

For examples, checkout the [example](/.example) folder.

## Support

This library tries to support as many signatures as possible, as long as they properly follow specifications.

### Generic / BIP-0137

This specification is considered [legacy signing in BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#legacy).

#### Supported

- Any wallet that does signing like Electrum, example:
  - Electrum: P2PKH, P2WPKH and P2SH-P2WPKH
  - Coinomi: P2PKH, P2WPKH and P2SH-P2WPKH
  - Samourai: P2PKH, P2WPKH and P2SH-P2WPKH
  - Mycelium: P2PKH, P2WPKH and P2SH-P2WPKH
- Any wallet that allows for legacy address signatures (P2PKH), example:
  - Bitcoin Core
- Any wallet that follows [BIP 137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki), example:
  - Trezor: P2PKH, P2WPKH and P2SH-P2WPKH
- Taproot (P2TR)
  - The verification is using the internal key, so only addresses without a tapscript are allowed.

#### Not supported

- Pay-to-Witness-Script-Hash (P2WSH)

### BIP-322

#### Supported

- [Simple singing](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#simple)
  - P2WPKH - Native Segwit
  - P2TR - Taproot

#### Not supported

- [Simple singing](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#simple) of other types
- [Full signing](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full)
- [Full singing (Proof of Funds)](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full-proof-of-funds)
- Multisig of any kind

### UniSat

The UniSat wallet [used to not follow established standards](https://github.com/BitonicNL/verify-signed-message/issues/3#issuecomment-1597101994) for signing messages when using non-taproot addresses. Specifically, it used to set incorrect recovery flags, resulting in signatures that are seen as invalid by Electrum, Bitcoin Core, Trezor, etc.

This seems to have been resolved in recent versions of Unisat. Not sure if they resolved it or one of their dependencies resolved it, but in our latest tests it worked as expected. 
If you run into issues, make sure you are using the latest version and generate new signatures.

## Development

This package is developed in-house and pushed from our internal repository to GitHub.

## Contributing

Contributions, issues and feature requests are welcome.

## License

Copyright © 2020-2026 Bitonic. This project is [ISC](/LICENSE) licensed.
