package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	PathToServe = "/myendpoint"

	ok200         = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, Slava!\r\n"
	badRequest400 = "HTTP/1.1 400 Bad Request\r\n\r\nBad Request.\r\n"
	notFound404   = "HTTP/1.1 404 Path Not Found\r\n\r\n404 Not Found\r\n"
	error500      = "HTTP/1.1 500 Internal Server Error\r\n\r\n500 Internal Error\r\n"

	maxRequestSize = 4096

	verbToServe = "GET"
)

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a port number!")
		return
	}

	port := ":" + arguments[1]
	listener, err := net.Listen("tcp4", port)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
		return
	}
	defer listener.Close()

	fmt.Printf("Server started on port %s\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	request, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading request: %v\n", err)
		conn.Write([]byte(error500))
		return
	}

	fmt.Printf("Request received from %s:\n%s", conn.RemoteAddr().String(), request)

	requestLine := strings.TrimSpace(request)
	parts := strings.Split(requestLine, " ")
	if len(parts) < 3 || parts[0] != verbToServe {
		conn.Write([]byte(badRequest400))
		return
	}

	if parts[1] != PathToServe {
		conn.Write([]byte(notFound404))
		return
	}

	conn.Write([]byte(ok200))
}
