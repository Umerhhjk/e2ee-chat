package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/umerhhjk/e2e-chat/internal/client/chat"
	"github.com/umerhhjk/e2e-chat/internal/client/db"
	"github.com/umerhhjk/e2e-chat/internal/client/state"
	"github.com/umerhhjk/e2e-chat/pkg/protocols"
)

func main() {
	// 1. Open the encrypted local database
	localDB, err := db.OpenLocalDatabase("local_chat.db", "my-super-secret-passphrase")
	if err != nil {
		log.Fatal("Failed to open local DB:", err)
	}
	defer localDB.Close()

	// 2. Connect to the Server's WebSocket
	// In a real app, you would log in via REST first and get a secure session ticket.
	myUserID := "user-alice-123"
	u := url.URL{Scheme: "ws", Host: "localhost:8080", Path: "/ws", RawQuery: "user_id=" + myUserID}
	log.Printf("Connecting to %s", u.String())

	wsConn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatal("WebSocket connection failed:", err)
	}
	defer wsConn.Close()

	// 3. Initialize the Cryptographic Pipeline
	replayMgr := &state.ReplayManager{DB: localDB}
	pipeline := &chat.Pipeline{
		DB:     localDB,
		Replay: replayMgr,
		WS:     wsConn,
		MyID:   myUserID,
	}

	log.Println("Connected successfully! You can now send messages.")

	// 4. Background Goroutine: Listen for incoming messages
	go func() {
		for {
			_, message, err := wsConn.ReadMessage()
			if err != nil {
				log.Println("Disconnected from server:", err)
				return
			}

			var env protocol.MessageEnvelope
			if err := json.Unmarshal(message, &env); err != nil {
				log.Println("Failed to parse incoming message:", err)
				continue
			}

			log.Printf("\n[Encrypted Envelope Received from %s] Processing...", env.SenderID)
			err = pipeline.HandleIncomingEnvelope(env)
			if err != nil {
				log.Println("Decryption/Validation failed:", err)
			} else {
				log.Println("Message successfully decrypted and saved to local DB!")
			}
		}
	}()

	// 5. Foreground Loop: Read terminal input to send messages
	scanner := bufio.NewScanner(os.Stdin)
	for {
		// Example prompt: Type "user-bob-456: Hello!" to send a message to Bob
		log.Print("Enter message (format: recipientID: message): ")
		if !scanner.Scan() {
			break
		}

		input := scanner.Text()
		parts := strings.SplitN(input, ":", 2)
		if len(parts) != 2 {
			log.Println("Invalid format. Use 'recipientID: message'")
			continue
		}

		recipientID := strings.TrimSpace(parts[0])
		plaintext := strings.TrimSpace(parts[1])

		// Note: In a complete app, you would fetch recipientKeys via the /keys REST API here.
		// For this CLI demo, we pass an empty bundle (which will fail the actual X3DH until wired up).
		dummyKeys := protocol.KeyBundle{}

		err = pipeline.SendMessage(recipientID, []byte(plaintext), dummyKeys)
		if err != nil {
			log.Println("Failed to send message:", err)
		} else {
			log.Println("Message encrypted and sent!")
		}
	}
}
