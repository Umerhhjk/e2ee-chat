package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/umerhhjk/e2e-chat/internal/server/api"
	"github.com/umerhhjk/e2e-chat/internal/server/ws"
)

func main() {
	// Update with your actual PostgreSQL credentials
	db, err := sql.Open("postgres", "postgres://postgres:1234@localhost/dbname?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	server := &api.Server{DB: db}
	hub := ws.NewHub(db) // hub is declared here

	http.HandleFunc("/register", api.RateLimitMiddleware(server.RegisterHandler))
	http.HandleFunc("/keys", api.RateLimitMiddleware(server.FetchKeysHandler))

	// Implement the WebSocket handler to use the 'hub' variable
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true }, // Allow all origins for local dev
	}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket Upgrade Error:", err)
			return
		}

		// In a real app, extract this from a secure session ticket.
		// For now, we grab it from the URL parameter: ws://localhost:8080/ws?user_id=123
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			conn.Close()
			return
		}

		// Register the connection in the hub
		hub.Register(userID, conn)
		log.Println("User connected to WebSocket:", userID)
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
