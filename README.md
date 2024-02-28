# Bitcoin Signed Message Verifier

[![Latest tag](https://img.shields.io/github/tag/bitonicnl/verify-signed-message.svg)](https://github.com/bitonicnl/verify-signed-message/tags)
![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.18-%23007d9c)
[![GoDoc](https://godoc.org/github.com/bitonicnl/verify-signed-message?status.svg)](https://pkg.go.dev/github.com/bitonicnl/verify-signed-message)
[![Tests status](https://github.com/bitonicnl/verify-signed-message/actions/workflows/test.yml/badge.svg)](https://github.com/BitonicNL/verify-signed-message/actions/workflows/test.yml)
[![Go report](https://goreportcard.com/badge/github.com/bitonicnl/verify-signed-message)](https://goreportcard.com/report/github.com/bitonicnl/verify-signed-message)
[![License](https://img.shields.io/github/license/bitonicnl/verify-signed-message)](./LICENSE)

> A simple Golang package with a single purpose, to verify messages signed via Bitcoin message signing (BMS).

## Requirements

- Golang 1.18+

## Installation

Your `$PATH` must contain the Go path and the Go `bin` path (see [GoLang's getting started](https://golang.org/doc/install#install) for more information). 

Once done, you can install this package: 
```bash
go get -u github.com/bitonicnl/verify-signed-message
```

## Usage

For examples, checkout the [example](/.example) folder.

## Support

This library tries to support as many signatures as possible.

**Current support:**
- Any wallet that does signing like Electrum, example:
  - Electrum: P2PKH, P2WPKH and P2WPKH-P2SH
  - Coinomi: P2PKH, P2WPKH and P2WPKH-P2SH
  - Samourai: P2PKH, P2WPKH and P2WPKH-P2SH
  - Mycelium: P2PKH, P2WPKH and P2WPKH-P2SH
- Any wallet that allows for legacy address signatures (P2PKH), example:
  - Bitcoin Core
- Any wallet that follows [BIP 137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki), example:
  - Trezor: P2PKH, P2WPKH and P2WPKH-P2SH
- Taproot (P2TR)
  - The verification is using the internal key, so only addresses without a tapscript are allowed.

**Currently not supported:**
- Pay-to-Witness-Script-Hash (P2WSH)
- BIP-322

## Development

This package is developed in-house and pushed from our internal repository to GitHub.

## Contributing

Contributions, issues and feature requests are welcome.

## License

Copyright © 2020-2024 Bitonic. This project is [ISC](/LICENSE) licensed.
