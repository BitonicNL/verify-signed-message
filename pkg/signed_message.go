package verifier

// SignedMessage is the representation of verification request.
type SignedMessage struct {
	// Address that was used to sign the Message with.
	Address string
	// Message that has been signed by the Address.
	Message string
	// Signature that has been provided and should be valid against the Address and Message.
	Signature string
}
