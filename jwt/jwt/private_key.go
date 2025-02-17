package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// GenerateRSAPrivateKey generates a new RSA private key with a specified bit size.
func GenerateRSAPrivateKey(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GenerateECDSAPrivateKey generates a new ECDSA private key with the specified elliptic curve.
func GenerateECDSAPrivateKey(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GenerateECDSA256PrivateKey generates a new ECDSA private key using the P-256 curve.
func GenerateECDSA256PrivateKey() (*ecdsa.PrivateKey, error) {
	return GenerateECDSAPrivateKey(elliptic.P256())
}

// GenerateECDSA384PrivateKey generates a new ECDSA private key using the P-384 curve.
func GenerateECDSA384PrivateKey() (*ecdsa.PrivateKey, error) {
	return GenerateECDSAPrivateKey(elliptic.P384())
}

// GenerateECDSA521PrivateKey generates a new ECDSA private key using the P-521 curve.
func GenerateECDSA521PrivateKey() (*ecdsa.PrivateKey, error) {
	return GenerateECDSAPrivateKey(elliptic.P521())
}
