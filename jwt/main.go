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

	ok, err := jwtHS256.Verify(tokenHS256)
	if err != nil {
		fmt.Println("Error verifying token:", err)
	}
	fmt.Println("Verify Token:", ok)

	//===

	privateKey, err := jwt.GenerateRSAPrivateKey()
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Example of creating an PS256 token
	jwtRS256 := jwt.New(
		jwt.WithAlgorithm(jwt.RS256),
		jwt.WithRSAKey(privateKey),
		jwt.WithExpiry(time.Hour),
	)

	// Set claims
	jwtRS256.SetClaim("username", "john_doe")

	// Encode the token
	tokenRS256, err := jwtRS256.Encode()
	if err != nil {
		fmt.Println("Error encoding RS256 token:", err)
		return
	}
	fmt.Println("RS256 Token:", tokenRS256)

	// Decode the token
	token, err = jwt.ParseJWT(tokenRS256)
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}
	fmt.Printf("Decoded Token: %+v\n", token)

	ok, err = jwtRS256.Verify(tokenRS256)
	if err != nil {
		fmt.Println("Error verifying token:", err)
	}
	fmt.Println("Verify Token:", ok)

	//===

	esPrivateKey, err := jwt.GenerateECDSA256PrivateKey()
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Example of creating an ES256 token
	jwtES256 := jwt.New(
		jwt.WithAlgorithm(jwt.ES256),
		jwt.WithECDSAKey(esPrivateKey),
		jwt.WithExpiry(time.Hour),
	)

	// Set claims
	jwtES256.SetClaim("username", "john_doe")

	// Encode the token
	tokenES256, err := jwtES256.Encode()
	if err != nil {
		fmt.Println("Error encoding ES256 token:", err)
		return
	}
	fmt.Println("ES256 Token:", tokenES256)

	// Decode the token
	token, err = jwt.ParseJWT(tokenES256)
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}
	fmt.Printf("Decoded Token: %+v\n", token)

	// TODO: fix ES verification
	ok, err = jwtES256.Verify(tokenES256)
	if err != nil {
		fmt.Println("Error verifying token:", err)
	}
	fmt.Println("Verify Token:", ok)

	//===

	// Example of creating an PS256 token
	jwtPS256 := jwt.New(
		jwt.WithAlgorithm(jwt.PS256),
		jwt.WithRSAKey(privateKey),
		jwt.WithExpiry(time.Hour),
	)

	// Set claims
	jwtPS256.SetClaim("username", "john_doe")

	// Encode the token
	tokenPS256, err := jwtPS256.Encode()
	if err != nil {
		fmt.Println("Error encoding PS256 token:", err)
		return
	}
	fmt.Println("PS256 Token:", tokenPS256)

	// Decode the token
	token, err = jwt.ParseJWT(tokenPS256)
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return
	}
	fmt.Printf("Decoded Token: %+v\n", token)

	// TODO: fix PS verification
	ok, err = jwtPS256.Verify(tokenPS256)
	if err != nil {
		fmt.Println("Error verifying token:", err)
	}
	fmt.Println("Verify Token:", ok)
}
