package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

// GenerateX25519KeyPair creates a new X25519 private/public key pair for DH exchanges.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, privKey.PublicKey(), nil
}

// GenerateEd25519KeyPair creates a new Ed25519 key pair for signing SPKs.
func GenerateEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, pub, err
}

// SignSPK signs the X25519 Signed Prekey's raw bytes using the Ed25519 Identity Private Key.
func SignSPK(identityPriv ed25519.PrivateKey, spkPub *ecdh.PublicKey) []byte {
	return ed25519.Sign(identityPriv, spkPub.Bytes())
}

// VerifySPK verifies the signature of a Signed Prekey using the sender's Ed25519 Identity Public Key.
func VerifySPK(identityPub ed25519.PublicKey, spkPub *ecdh.PublicKey, signature []byte) error {
	if !ed25519.Verify(identityPub, spkPub.Bytes(), signature) {
		return errors.New("invalid SPK signature")
	}
	return nil
}