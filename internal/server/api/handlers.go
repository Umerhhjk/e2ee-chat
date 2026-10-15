package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/umerhhjk/e2e-chat/pkg/protocols"
	"golang.org/x/crypto/argon2"
)

type Server struct {
	DB *sql.DB
}

// RegisterRequest defines the expected JSON payload for user registration
type RegisterRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	IdentityKey []byte `json:"identity_key"`
	SPK         struct {
		KeyID     int    `json:"key_id"`
		PubKey    []byte `json:"pub_key"`
		Signature []byte `json:"signature"`
	} `json:"spk"`
	OPKs []struct {
		KeyID  int    `json:"key_id"`
		PubKey []byte `json:"pub_key"`
	} `json:"opks"`
}

// hashPassword uses Argon2id for server-side password hashing
func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash)
}

func (s *Server) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hashedPw := hashPassword(req.Password)

	tx, _ := s.DB.Begin()
	defer tx.Rollback()

	// Insert User
	var userID string
	err := tx.QueryRow(`INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`,
		req.Username, hashedPw).Scan(&userID)
	if err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Insert Identity Key & Signed Prekey
	tx.Exec(`INSERT INTO identity_keys (user_id, public_key) VALUES ($1, $2)`, userID, req.IdentityKey)
	tx.Exec(`INSERT INTO signed_prekeys (user_id, key_id, public_key, signature) VALUES ($1, $2, $3, $4)`,
		userID, req.SPK.KeyID, req.SPK.PubKey, req.SPK.Signature)

	// Insert Batch of One-Time Prekeys
	for _, opk := range req.OPKs {
		tx.Exec(`INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES ($1, $2, $3)`,
			userID, opk.KeyID, opk.PubKey)
	}

	tx.Commit()
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) FetchKeysHandler(w http.ResponseWriter, r *http.Request) {
	targetUserID := r.URL.Query().Get("user_id")

	tx, _ := s.DB.Begin()
	defer tx.Rollback()

	bundle := protocol.KeyBundle{}

	// Fetch IK and SPK
	err := tx.QueryRow(`
		SELECT ik.public_key, spk.key_id, spk.public_key, spk.signature 
		FROM identity_keys ik 
		JOIN signed_prekeys spk ON ik.user_id = spk.user_id 
		WHERE ik.user_id = $1`, targetUserID).
		Scan(&bundle.IdentityKey, &bundle.SPKID, &bundle.SPKPub, &bundle.SPKSig)

	if err != nil {
		http.Error(w, "User keys not found", http.StatusNotFound)
		return
	}

	// Atomically pop one OPK using FOR UPDATE SKIP LOCKED
	err = tx.QueryRow(`
		DELETE FROM one_time_prekeys 
		WHERE key_id = (
			SELECT key_id FROM one_time_prekeys 
			WHERE user_id = $1 LIMIT 1 FOR UPDATE SKIP LOCKED
		) RETURNING key_id, public_key`, targetUserID).
		Scan(&bundle.OPKID, &bundle.OPKPub)

	// If err == sql.ErrNoRows, OPKs are exhausted (bundle.OPKID remains nil). We only return a 500 for other DB errors.
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "Database error fetching OPK", http.StatusInternalServerError)
		return
	}

	tx.Commit()
	json.NewEncoder(w).Encode(bundle)
}
