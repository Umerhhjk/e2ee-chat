package ws

import (
	"database/sql"
	"encoding/json"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/umerhhjk/e2e-chat/pkg/protocols"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[string]*websocket.Conn // Maps UserID -> Active Connection
	db      *sql.DB
}

func NewHub(db *sql.DB) *Hub {
	return &Hub{
		clients: make(map[string]*websocket.Conn),
		db:      db,
	}
}

func (h *Hub) Register(userID string, conn *websocket.Conn) {
	h.mu.Lock()
	h.clients[userID] = conn
	h.mu.Unlock()

	// Push offline messages immediately upon connection
	go h.flushOfflineQueue(userID, conn)
}

func (h *Hub) Unregister(userID string) {
	h.mu.Lock()
	delete(h.clients, userID)
	h.mu.Unlock()
}

// RouteMessage attempts to send live, or falls back to Postgres queue
func (h *Hub) RouteMessage(env protocol.MessageEnvelope) {
	h.mu.RLock()
	conn, isOnline := h.clients[env.RecipientID]
	h.mu.RUnlock()

	if isOnline {
		// Send direct
		payload, _ := json.Marshal(env)
		conn.WriteMessage(websocket.TextMessage, payload)
	} else {
		// Bob is offline, queue the encrypted envelope
		h.db.Exec(`
			INSERT INTO offline_messages 
			(sender_id, recipient_id, ek_a, spk_id, opk_id, message_id, seq_num, nonce, ciphertext) 
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			env.SenderID, env.RecipientID, env.EphemeralKey, env.SPKID, env.OPKID,
			env.MessageID, env.SeqNum, env.Nonce, env.Ciphertext)
	}
}

func (h *Hub) flushOfflineQueue(userID string, conn *websocket.Conn) {
	rows, _ := h.db.Query(`SELECT id, sender_id, ek_a, spk_id, opk_id, message_id, seq_num, nonce, ciphertext FROM offline_messages WHERE recipient_id = $1 ORDER BY seq_num ASC`, userID)
	defer rows.Close()

	var msgIDs []string
	for rows.Next() {
		var env protocol.MessageEnvelope
		var rowID string
		rows.Scan(&rowID, &env.SenderID, &env.EphemeralKey, &env.SPKID, &env.OPKID, &env.MessageID, &env.SeqNum, &env.Nonce, &env.Ciphertext)

		payload, _ := json.Marshal(env)
		conn.WriteMessage(websocket.TextMessage, payload)
		msgIDs = append(msgIDs, rowID)
	}

	// In production, delete upon client ACK. Here we delete post-flush.
	for _, id := range msgIDs {
		h.db.Exec(`DELETE FROM offline_messages WHERE id = \$1`, id)
	}
}
