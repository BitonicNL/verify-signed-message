package main

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/bitonicnl/verify-signed-message/pkg"
)

func main() {
	// Bitcoin Mainnet
	fmt.Println(verifier.VerifyWithChain(verifier.SignedMessage{
		Address:   "18J72YSM9pKLvyXX1XAjFXA98zeEvxBYmw",
		Message:   "Test123",
		Signature: "Gzhfsw0ItSrrTCChykFhPujeTyAcvVxiXwywxpHmkwFiKuUR2ETbaoFcocmcSshrtdIjfm8oXlJoTOLosZp3Yc8=",
	}, &chaincfg.MainNetParams))

	// Bitcoin Testnet3
	fmt.Println(verifier.VerifyWithChain(verifier.SignedMessage{
		Address:   "tb1qr97cuq4kvq7plfetmxnl6kls46xaka78n2288z",
		Message:   "The outage comes at a time when bitcoin has been fast approaching new highs not seen since June 26, 2019.",
		Signature: "H/bSByRH7BW1YydfZlEx9x/nt4EAx/4A691CFlK1URbPEU5tJnTIu4emuzkgZFwC0ptvKuCnyBThnyLDCqPqT10=",
	}, &chaincfg.TestNet3Params))
}
