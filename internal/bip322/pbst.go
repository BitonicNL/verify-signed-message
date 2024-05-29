package bip322

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/bitonicnl/verify-signed-message/internal"
)

// Constants for the toSpend transaction.
const (
	// toSpendVersion contains the transaction version.
	toSpendVersion = 0
	// toSpendLockTime contains the transaction lock time.
	toSpendLockTime = 0
	// toSpendInputHash contains the dummy input hash.
	toSpendInputHash = "0000000000000000000000000000000000000000000000000000000000000000"
	// toSpendInputIndex contains the dummy input index.
	toSpendInputIndex = 0xFFFFFFFF
	// toSpendInputSeq contains the sequence number for the input.
	toSpendInputSeq = 0
	// toSpendOutputValue contains the output value (in satoshis).
	toSpendOutputValue = 0
)

// Constants for the toSign transaction.
const (
	// toSignVersion contains the transaction version.
	toSignVersion = 0
	// toSignLockTime contains the transaction lock time.
	toSignLockTime = 0
	// toSignInputSeq contains the sequence number for the input.
	toSignInputSeq = 0
	// toSignOutputValue contains the output value (in satoshis).
	toSignOutputValue = 0
)

// BuildToSpendTx builds a toSpend transaction based on the BIP-322 spec. It requires the message that is signed and the address that produced the signature.
//
// For more details, refer: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full
func BuildToSpendTx(msg []byte, address btcutil.Address) (*wire.MsgTx, error) {
	// Create a new transaction
	psbt := wire.NewMsgTx(toSpendVersion)
	psbt.LockTime = toSpendLockTime

	// Create an outpoint for the input
	inputHash, err := chainhash.NewHashFromStr(toSpendInputHash)
	if err != nil {
		// This error indicates a programming error since the input hash is predefined
		panic(err)
	}
	outPoint := wire.NewOutPoint(inputHash, toSpendInputIndex)

	// Generate the signature script for the input
	script, err := toSpendSignatureScript(msg)
	if err != nil {
		return nil, err
	}

	// Create the input using the outpoint and signature script
	input := wire.NewTxIn(outPoint, script, nil)
	input.Sequence = toSpendInputSeq

	// Create the output paying to the provided address
	pkScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		return nil, err
	}

	// Create the output using the pay-to-address script
	output := wire.NewTxOut(toSpendOutputValue, pkScript)

	// Add the input and output to the transaction
	psbt.AddTxIn(input)
	psbt.AddTxOut(output)

	return psbt, nil
}

// BuildToSignTx builds a toSign transaction based on the BIP-322 spec. // It requires the toSpend transaction that it spends.
//
// For more details, refer: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full
func BuildToSignTx(toSpend *wire.MsgTx) *wire.MsgTx {
	// Create a new transaction
	toSign := wire.NewMsgTx(toSignVersion)
	toSign.LockTime = toSignLockTime

	// Specify the input outpoint
	// As the input is from the toSpend transaction, the index is 0
	inputHash := toSpend.TxHash()
	outPoint := wire.NewOutPoint(&inputHash, 0)

	// Create the input using the out point
	input := wire.NewTxIn(outPoint, nil, nil)
	input.Sequence = toSignInputSeq

	// Create the output with an unspendable script
	output := wire.NewTxOut(toSignOutputValue, buildSignPkScript())

	// Add the input and output to the transaction
	toSign.AddTxIn(input)
	toSign.AddTxOut(output)

	return toSign
}

// toSpendSignatureScript creates the signature script for the input of the toSpend transaction. It follows the BIP-322 specification.
//
// For more details, refer: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full
func toSpendSignatureScript(msg []byte) ([]byte, error) {
	// Create a new script builder
	builder := txscript.NewScriptBuilder()

	// Add OP_0 to initialize the witness stack
	builder.AddOp(txscript.OP_0)

	// Create the magic message as specified in BIP-322
	data := internal.CreateMagicMessageBIP322(msg)
	builder.AddData(data[:])

	// Generate the script
	script, err := builder.Script()
	if err != nil {
		// Since this is based on the incoming message, this could happen
		return nil, err
	}

	return script, nil
}

// buildSignPkScript creates the public key script for the output of the toSign transaction. It follows the BIP-322 specification.
//
// For more details, refer: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#full
func buildSignPkScript() []byte {
	// Create a new script builder
	builder := txscript.NewScriptBuilder()

	// Add OP_RETURN opcode to mark the output as unspendable
	builder.AddOp(txscript.OP_RETURN)

	// Generate the script
	script, err := builder.Script()
	if err != nil {
		// Since we are constructing the script, this error should not occur in practice
		panic(err)
	}

	return script
}
