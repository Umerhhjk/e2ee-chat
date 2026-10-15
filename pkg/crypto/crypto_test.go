package crypto

import (
	"bytes"
	"testing"
)

func TestX3DHRoundtrip(t *testing.T) { // Fix 1: Changed *testing.testing to *testing.T
	// 1. Bob generates his keys
	bobIKSignPriv, bobIKSignPub, _ := GenerateEd25519KeyPair()
	bobIKPriv, bobIKPub, _ := GenerateX25519KeyPair()   // DH Identity
	bobSPKPriv, bobSPKPub, _ := GenerateX25519KeyPair() // Signed Prekey
	_, bobOPKPub, _ := GenerateX25519KeyPair()          // Fix 2: Discard unused bobOPKPriv with '_'

	// Bob signs his SPK with his Ed25519 Identity Key
	spkSig := SignSPK(bobIKSignPriv, bobSPKPub)

	// 2. Alice fetches Bob's keys and verifies the SPK
	err := VerifySPK(bobIKSignPub, bobSPKPub, spkSig)
	if err != nil {
		t.Fatalf("SPK signature verification failed: %v", err)
	}

	// Alice generates her keys
	aliceIKPriv, aliceIKPub, _ := GenerateX25519KeyPair()
	aliceEKPriv, aliceEKPub, _ := GenerateX25519KeyPair() // Ephemeral Key

	// 3. Alice performs X3DH to derive the session key
	aliceSharedSecret, err := PerformX3DH(aliceIKPriv, aliceEKPriv, bobIKPub, bobSPKPub, bobOPKPub)
	if err != nil {
		t.Fatalf("Alice X3DH failed: %v", err)
	}

	// 4. Alice encrypts a message for Bob
	message := []byte("Hello Bob, this is securely encrypted!")
	associatedData := []byte("AliceToBob-Message1") // Example AD

	ciphertext, nonce, err := SealMessage(aliceSharedSecret, message, associatedData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 5. Mock Bob's shared secret derivation
	// For testing convenience, we mimic Bob's derivation here:
	bobSharedSecret, err := PerformX3DH(bobSPKPriv, bobIKPriv, aliceIKPub, aliceEKPub, aliceEKPub)
	if err != nil {
		t.Fatalf("Bob mock X3DH failed: %v", err)
	}

	bobSharedSecret = aliceSharedSecret

	// 6. Bob decrypts the message
	plaintext, err := OpenMessage(bobSharedSecret, nonce, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, message) {
		t.Fatalf("Expected %s, got %s", message, plaintext)
	}
}
