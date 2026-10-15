package state

import (
	"database/sql"
	"errors"
)

type ReplayManager struct {
	DB *sql.DB
}

// CheckDuplicateMessageID verifies if a 16-byte message ID has already been seen.
func (rm *ReplayManager) CheckDuplicateMessageID(msgID []byte) (bool, error) {
	var count int
	err := rm.DB.QueryRow("SELECT count(*) FROM seen_messages WHERE message_id = $1", msgID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ValidateAndAdvanceCounter implements a 64-bit sliding window for incoming sequence numbers.
func (rm *ReplayManager) ValidateAndAdvanceCounter(contactID string, incomingCounter uint64) (bool, error) {
	tx, err := rm.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var highest uint64
	var window uint64
	err = tx.QueryRow("SELECT highest_recv_seq, receive_window FROM conversations WHERE contact_id = $1 FOR UPDATE", contactID).Scan(&highest, &window)
	if err != nil {
		if err == sql.ErrNoRows {
			// First message from this contact
			_, err = tx.Exec("INSERT INTO conversations (contact_id, highest_recv_seq, receive_window, send_sequence, shared_secret) VALUES ($1, $2, $3, 0, x'') ON CONFLICT DO NOTHING", contactID, incomingCounter, 1)
			tx.Commit()
			return true, nil
		}
		return false, err
	}

	// If counter is too old
	if incomingCounter < highest-64 {
		return false, errors.New("message sequence too old (outside window)")
	}

	// If counter is inside the current window
	if incomingCounter <= highest {
		diff := highest - incomingCounter
		bitmask := uint64(1) << diff
		if (window & bitmask) != 0 {
			return false, errors.New("message replayed (sequence already seen)")
		}
		window |= bitmask
	} else {
		// Counter is ahead of the window; shift window left
		diff := incomingCounter - highest
		if diff >= 64 {
			window = 1 // Shifted entirely out, new window starts at 1
		} else {
			window = (window << diff) | 1
		}
		highest = incomingCounter
	}

	_, err = tx.Exec("UPDATE conversations SET highest_recv_seq = $1, receive_window = $2 WHERE contact_id = $3", highest, window, contactID)
	if err != nil {
		return false, err
	}

	tx.Commit()
	return true, nil
}
