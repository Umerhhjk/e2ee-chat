package protocol

// Envelope represents an E2EE message sent from Alice to Bob
type MessageEnvelope struct {
	MessageID   []byte `json:"message_id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	SeqNum      int64  `json:"seq_num"`

	// Routing metadata for X3DH
	EphemeralKey []byte `json:"ephemeral_key"`
	SPKID        int    `json:"used_spk_id"`
	OPKID        *int   `json:"used_opk_id,omitempty"` // Nullable if OPKs are exhausted

	// Encrypted Payload
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"` // Contains AES-GCM auth tag
}

// KeyBundle is requested by Alice to initiate X3DH with Bob
type KeyBundle struct {
	IdentityKey []byte `json:"identity_key"`
	SPKID       int    `json:"spk_id"`
	SPKPub      []byte `json:"spk_pub"`
	SPKSig      []byte `json:"spk_sig"`
	OPKID       *int   `json:"opk_id,omitempty"`
	OPKPub      []byte `json:"opk_pub,omitempty"`
}
