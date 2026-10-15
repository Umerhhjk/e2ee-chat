package crypto

import (
	"crypto/ecdh"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// PerformX3DH executes the initiator side of the X3DH protocol.
// opkB is optional (can be nil) if the recipient's one-time prekeys are exhausted.
func PerformX3DH(ikA, ekA *ecdh.PrivateKey, ikB, spkB, opkB *ecdh.PublicKey) ([]byte, error) {
	if ikA == nil || ekA == nil || ikB == nil || spkB == nil {
		return nil, errors.New("missing required keys for X3DH")
	}

	// DH1 = IK_A (priv) * SPK_B (pub)
	dh1, err := ikA.ECDH(spkB)
	if err != nil {
		return nil, err
	}

	// DH2 = EK_A (priv) * IK_B (pub)
	dh2, err := ekA.ECDH(ikB)
	if err != nil {
		return nil, err
	}

	// DH3 = EK_A (priv) * SPK_B (pub)
	dh3, err := ekA.ECDH(spkB)
	if err != nil {
		return nil, err
	}

	var ikm []byte
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)

	// DH4 = EK_A (priv) * OPK_B (pub) (Optional)
	if opkB != nil {
		dh4, err := ekA.ECDH(opkB)
		if err != nil {
			return nil, err
		}
		ikm = append(ikm, dh4...)
	}

	// Derive 32-byte AES key using HKDF-SHA256
	// Using a nil salt as per standard X3DH (or use a 32-byte zero salt), and domain-specific info
	hkdfReader := hkdf.New(sha256.New, ikm, nil, []byte("chatapp-aes-gcm"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}

	return aesKey, nil
}