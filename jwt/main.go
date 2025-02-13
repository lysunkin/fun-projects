package main

import (
	"fmt"
	"time"

	"jwt/jwt"
)

func main() {
	// Example of creating an HS256 token
	jwtHS256 := jwt.New(
		jwt.WithAlgorithm(jwt.HS256),
		jwt.WithSecretKey("your-secret-key"),
		jwt.WithExpiry(time.Hour),
	)

	// Set claims
	jwtHS256.SetClaim("username", "john_doe")

	// Encode the token
	tokenHS256, err := jwtHS256.Encode()
	if err != nil {
		fmt.Println("Error encoding HS256 token:", err)
		return
	}
	fmt.Println("HS256 Token:", tokenHS256)

	// Decode the token
	token, err := jwt.ParseJWT(tokenHS256)
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}
	fmt.Printf("Decoded Token: %+v\n", token)
}
