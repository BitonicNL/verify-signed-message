package internal

import (
	"bytes"

	"github.com/btcsuite/btcd/wire"
)

// varIntProtoVer is the protocol version to use for serializing N as a VarInt
// Copied from https://github.com/btcsuite/btcutil/blob/master/gcs/gcs.go#L37
const varIntProtoVer uint32 = 0

// Signed message are prepended with this magicMessage
// Taken from https://bitcoin.stackexchange.com/a/77325
const magicMessage = "\x18Bitcoin Signed Message:\n"

// WriteVarInt copied from https://github.com/btcsuite/btcutil/blob/master/gcs/gcs.go#L225
func CreateMagicMessage(message string) string {
	buffer := bytes.Buffer{}
	buffer.Grow(wire.VarIntSerializeSize(uint64(len(message))))

	// If we cannot write the VarInt, just panic since that should never happen
	if err := wire.WriteVarInt(&buffer, varIntProtoVer, uint64(len(message))); err != nil {
		panic(err)
	}

	return magicMessage + buffer.String() + message
}
