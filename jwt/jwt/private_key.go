package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// GenerateRSAPrivateKey generates a new RSA private key
func GenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GenerateECDSAPrivateKey generates a new ECDSA private key
func GenerateECDSAPrivateKey(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func GenerateECDSA256PrivateKey() (*ecdsa.PrivateKey, error) {
	return GenerateECDSAPrivateKey(elliptic.P256()) // P-256 curve for ES256
}

func GenerateECDSA384PrivateKey() (*ecdsa.PrivateKey, error) {
	return GenerateECDSAPrivateKey(elliptic.P384())
}

func GenerateECDSA512PrivateKey() (*ecdsa.PrivateKey, error) {
	return GenerateECDSAPrivateKey(elliptic.P521())
}
