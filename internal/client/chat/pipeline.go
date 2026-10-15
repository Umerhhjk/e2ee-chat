package chat

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gorilla/websocket"
	"github.com/umerhhjk/e2e-chat/internal/client/state"
	"github.com/umerhhjk/e2e-chat/pkg/crypto"
	protocol "github.com/umerhhjk/e2e-chat/pkg/protocols"
	"golang.org/x/crypto/hkdf"
)

type Pipeline struct {
	DB     *sql.DB
	Replay *state.ReplayManager
	WS     *websocket.Conn
	MyID   string
}

// SendMessage executes X3DH, AEAD encryption, and transmits over WebSocket.
func (p *Pipeline) SendMessage(recipientID string, plaintext []byte, recipientKeys protocol.KeyBundle) error {
	// 1. Load Local Keys
	myIKPriv, _, _ := crypto.GenerateX25519KeyPair() // Fetch from local_keys DB table
	myEKPriv, myEKPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return err
	}

	// 2. Parse Recipient Public Keys
	bobIKPub, _ := ecdh.X25519().NewPublicKey(recipientKeys.IdentityKey)
	bobSPKPub, _ := ecdh.X25519().NewPublicKey(recipientKeys.SPKPub)
	var bobOPKPub *ecdh.PublicKey
	if recipientKeys.OPKPub != nil {
		bobOPKPub, _ = ecdh.X25519().NewPublicKey(recipientKeys.OPKPub)
	}

	// 3. X3DH Agreement
	sharedSecret, err := crypto.PerformX3DH(myIKPriv, myEKPriv, bobIKPub, bobSPKPub, bobOPKPub)
	if err != nil {
		return err
	}

	// 4. Update Send Sequence
	var seqNum int64
	p.DB.QueryRow("UPDATE conversations SET send_sequence = send_sequence + 1 WHERE contact_id = $1 RETURNING send_sequence", recipientID).Scan(&seqNum)

	// 5. Encrypt with Associated Data
	rawMsgID := make([]byte, 16)
	rand.Read(rawMsgID) // Proper way to generate random 16-byte message ID

	ad := fmt.Sprintf("%s||%s||%x||%d", p.MyID, recipientID, rawMsgID, seqNum)
	ciphertext, nonce, err := crypto.SealMessage(sharedSecret, plaintext, []byte(ad))
	if err != nil {
		return err
	}

	// 6. Push to Network
	env := protocol.MessageEnvelope{
		MessageID:    rawMsgID,
		SenderID:     p.MyID,
		RecipientID:  recipientID,
		SeqNum:       seqNum,
		EphemeralKey: myEKPub.Bytes(),
		SPKID:        recipientKeys.SPKID,
		OPKID:        recipientKeys.OPKID,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}

	payload, _ := json.Marshal(env)
	return p.WS.WriteMessage(websocket.TextMessage, payload)
}

// HandleIncomingEnvelope processes received messages, validates them, and stores plaintext.
func (p *Pipeline) HandleIncomingEnvelope(env protocol.MessageEnvelope) error {
	// 1. Check Exact Match Deduplication
	isDup, err := p.Replay.CheckDuplicateMessageID(env.MessageID)
	if err != nil || isDup {
		return errors.New("duplicate message dropped")
	}

	// 2. Load Sender's Public Key & My Private Keys (Mocked for brevity)
	aliceIKPub, _ := ecdh.X25519().NewPublicKey(make([]byte, 32)) // Fetch from local contacts
	aliceEKPub, _ := ecdh.X25519().NewPublicKey(env.EphemeralKey)
	myIKPriv, _, _ := crypto.GenerateX25519KeyPair()
	mySPKPriv, _, _ := crypto.GenerateX25519KeyPair()
	var myOPKPriv *ecdh.PrivateKey // Query one_time_prekeys WHERE key_id = env.OPKID

	if env.OPKID != nil {
		// Mock querying: SELECT priv_key FROM one_time_prekeys WHERE key_id = env.OPKID
		myOPKPriv, _, _ = crypto.GenerateX25519KeyPair()
	}

	// 3. X3DH Responder Path (Inline calculation to correct type mapping)
	dh1, _ := mySPKPriv.ECDH(aliceIKPub)
	dh2, _ := myIKPriv.ECDH(aliceEKPub)
	dh3, _ := mySPKPriv.ECDH(aliceEKPub)

	var ikm []byte
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)

	if myOPKPriv != nil {
		dh4, _ := myOPKPriv.ECDH(aliceEKPub)
		ikm = append(ikm, dh4...)
	}

	hkdfReader := hkdf.New(sha256.New, ikm, nil, []byte("chatapp-aes-gcm"))
	sharedSecret := make([]byte, 32)
	io.ReadFull(hkdfReader, sharedSecret)

	// 4. Authenticate & Decrypt
	ad := fmt.Sprintf("%s||%s||%x||%d", env.SenderID, p.MyID, env.MessageID, env.SeqNum)
	plaintext, err := crypto.OpenMessage(sharedSecret, env.Nonce, env.Ciphertext, []byte(ad))
	if err != nil {
		return errors.New("decryption/authentication failed")
	}

	// 5. Sliding Window Validation
	valid, err := p.Replay.ValidateAndAdvanceCounter(env.SenderID, uint64(env.SeqNum))
	if err != nil || !valid {
		return errors.New("replay detected")
	}

	// 6. Commit State Changes
	tx, _ := p.DB.Begin()
	tx.Exec("INSERT INTO seen_messages (message_id) VALUES ($1)", env.MessageID)
	tx.Exec("INSERT INTO messages (id, message_id, conversation_id, sender_id, content, is_outgoing) VALUES (?, ?, ?, ?, ?, ?)",
		"uuid-placeholder", env.MessageID, env.SenderID, env.SenderID, string(plaintext), false)

	if env.OPKID != nil {
		tx.Exec("DELETE FROM one_time_prekeys WHERE key_id = $1", *env.OPKID)
	}

	return tx.Commit()
}
