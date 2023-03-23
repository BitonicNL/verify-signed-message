# Bitcoin Signed Message Verifier
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

## Contributing

Contributions, issues and feature requests are welcome.

## License

Copyright © 2022 Bitonic. This project is [ISC](/LICENSE) licensed.
