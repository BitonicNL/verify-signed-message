# Bitcoin Signed Message Verifier

[![tag](https://img.shields.io/github/tag/bitonicnl/verify-signed-message.svg)](https://github.com/bitonicnl/verify-signed-message/tags)
![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.18-%23007d9c)
[![GoDoc](https://godoc.org/github.com/bitonicnl/verify-signed-message?status.svg)](https://pkg.go.dev/github.com/bitonicnl/verify-signed-message)
![Build Status](https://github.com/bitonicnl/verify-signed-message/actions/workflows/test.yml/badge.svg)
[![Go report](https://goreportcard.com/badge/github.com/bitonicnl/verify-signed-message)](https://goreportcard.com/report/github.com/bitonicnl/verify-signed-message)
[![Contributors](https://img.shields.io/github/contributors/bitonicnl/verify-signed-message)](https://github.com/bitonicnl/verify-signed-message/graphs/contributors)
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

```go
package main

import (
    "fmt"
    
    "github.com/btcsuite/btcd/chaincfg"

    "github.com/bitonicnl/verify-signed-message/pkg"
)

func main()  {
    // Bitcoin Mainnet
    fmt.Println(verifier.Verify(verifier.SignedMessage{
        Address:   "18J72YSM9pKLvyXX1XAjFXA98zeEvxBYmw",
        Message:   "Test123",
        Signature: "Gzhfsw0ItSrrTCChykFhPujeTyAcvVxiXwywxpHmkwFiKuUR2ETbaoFcocmcSshrtdIjfm8oXlJoTOLosZp3Yc8=",
    }))

    // Bitcoin Testnet3
    fmt.Println(verifier.VerifyWithChain(verifier.SignedMessage{
        Address:   "tb1qr97cuq4kvq7plfetmxnl6kls46xaka78n2288z",
        Message:   "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.",
        Signature: "H/bSByRH7BW1YydfZlEx9x/nt4EAx/4A691CFlK1URbPEU5tJnTIu4emuzkgZFwC0ptvKuCnyBThnyLDCqPqT10=",
    }, &chaincfg.TestNet3Params))
}
```

In this example it will output `true, <nil>`, since the signature is valid and there are no errors.

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

**Currently not supported:**
- Pay-to-Witness-Script-Hash (P2WSH)
- Taproot ([as there is no consensus](https://github.com/trezor/trezor-firmware/issues/1943))

## Development

This package is developed in-house and pushed from our internal repository to GitHub.

## Contributing

Contributions, issues and feature requests are welcome.

## License

Copyright © 2020-2023 Bitonic. This project is [ISC](/LICENSE) licensed.
