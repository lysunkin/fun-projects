package main

import (
	"fmt"
	"net"
)

func main() {
	// Listen on a UDP address and port
	addr := net.UDPAddr{
		Port: 8080,
		IP:   net.ParseIP("127.0.0.1"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		fmt.Println("Error starting UDP server:", err)
		return
	}
	defer conn.Close()

	fmt.Println("UDP server is running on", addr.String())

	buf := make([]byte, 1024)
	for {
		// Read data from the connection
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading from UDP connection:", err)
			continue
		}

		fmt.Printf("Received '%s' from %s\n", string(buf[:n]), clientAddr)

		// Echo the data back to the client
		_, err = conn.WriteToUDP([]byte("Acknowledged: "+string(buf[:n])), clientAddr)
		if err != nil {
			fmt.Println("Error sending response:", err)
		}
	}
}
