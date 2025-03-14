package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	serverAddr := net.UDPAddr{
		Port: 8080,
		IP:   net.ParseIP("127.0.0.1"),
	}

	conn, err := net.DialUDP("udp", nil, &serverAddr)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	fmt.Println("Connected to UDP server at", serverAddr.String())

	for i := 0; i < 5; i++ {
		message := fmt.Sprintf("Message %d", i+1)
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Println("Error sending message:", err)
			continue
		}
		fmt.Printf("Sent: %s\n", message)

		// Read the server's response
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading response:", err)
			continue
		}
		fmt.Printf("Server says: %s\n", string(buf[:n]))

		time.Sleep(1 * time.Second)
	}
}
