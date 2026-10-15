package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// SealMessage encrypts a plaintext message using AES-256-GCM.
// It generates a secure random 12-byte nonce and returns both the ciphertext and the nonce.
// Additional Data (AD) can optionally be passed to bind the ciphertext to message metadata.
func SealMessage(aesKey []byte, plaintext []byte, ad []byte) (ciphertext []byte, nonce []byte, err error) {
	if len(aesKey) != 32 {
		return nil, nil, errors.New("AES key must be 32 bytes")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Seal appends the auth tag to the ciphertext automatically
	ciphertext = aesGCM.Seal(nil, nonce, plaintext, ad)
	return ciphertext, nonce, nil
}

// OpenMessage decrypts an AES-256-GCM message and validates its authenticity.
func OpenMessage(aesKey []byte, nonce []byte, ciphertext []byte, ad []byte) ([]byte, error) {
	if len(aesKey) != 32 {
		return nil, errors.New("AES key must be 32 bytes")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Open verifies the auth tag and decrypts the payload
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, errors.New("decryption failed or message tampered")
	}

	return plaintext, nil
}