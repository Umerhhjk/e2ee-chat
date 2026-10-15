package db

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"golang.org/x/crypto/argon2"
)

// OpenLocalDatabase derives a key from the passphrase and opens the encrypted SQLite DB.
func OpenLocalDatabase(dbPath, passphrase string) (*sql.DB, error) {
	// Derive 32-byte key using Argon2id (using static salt for local DB binding, or fetch from unencrypted config)
	salt := []byte("local-db-static-salt") // In production, generate securely and store alongside DB
	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	hexKey := hex.EncodeToString(key)

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// The PRAGMA key must be the very first operation.
	keyQuery := fmt.Sprintf("PRAGMA key = \"x'%s'\";", hexKey)
	if _, err := db.Exec(keyQuery); err != nil {
		db.Close()
		return nil, errors.New("failed to set database key")
	}

	// Optimize for security and concurrent access
	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA secure_delete = ON;"); err != nil {
		db.Close()
		return nil, err
	}

	// Verify encryption key is correct by attempting a read
	var test int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master;").Scan(&test); err != nil {
		db.Close()
		return nil, errors.New("invalid passphrase or corrupt database")
	}

	return db, nil
}
