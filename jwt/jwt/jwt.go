package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"

	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"

	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"

	PS256 = "PS256"
	PS384 = "PS384"
	PS512 = "PS512"

	ExpirationKey = "exp"
	IssuedAtKey   = "iat"
	AlgorithmKey  = "alg"
	TypeKey       = "typ"

	TypeValue = "JWT"
)

// Base64URLEncode encodes data to a URL-safe base64 string
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// hashData hashes the given data using the provided hash function
func hashData(data string, hashFunc func() hash.Hash) []byte {
	hasher := hashFunc()
	hasher.Write([]byte(data))
	return hasher.Sum(nil)
}

// JWT struct for encoding JWT tokens
type JWT struct {
	secretKey       string                 // Secret key for HMAC algorithms
	Signature       string                 // Signature part of the JWT token
	Algorithm       string                 // JWT algorithm (HS256, RS256, etc.)
	Payload         map[string]interface{} // Claims to be encoded into the token
	rsaPrivateKey   *rsa.PrivateKey        // private key for RSXXX, PSXXX algorithms
	ecdsaPrivateKey *ecdsa.PrivateKey      // private key for ESXXX algorithms
}

type JWTOption func(*JWT)

func WithAlgorithm(algorithm string) JWTOption {
	return func(j *JWT) {
		j.Algorithm = algorithm
	}
}

func WithExpiry(expiry time.Duration) JWTOption {
	return func(j *JWT) {
		j.Payload[ExpirationKey] = time.Now().Add(expiry).Unix()
	}
}

func WithSecretKey(secretKey string) JWTOption {
	return func(j *JWT) {
		j.secretKey = secretKey
	}
}

func WithClaims(claims map[string]interface{}) JWTOption {
	return func(j *JWT) {
		j.Payload = claims
	}
}

func WithRSAKey(privateKey *rsa.PrivateKey) JWTOption {
	return func(j *JWT) {
		j.rsaPrivateKey = privateKey
	}
}

func WithECDSAKey(privateKey *ecdsa.PrivateKey) JWTOption {
	return func(j *JWT) {
		j.ecdsaPrivateKey = privateKey
	}
}

func WithPayload(payload map[string]interface{}) JWTOption {
	return func(j *JWT) {
		for k, v := range payload {
			j.Payload[k] = v
		}
	}
}

// New creates a new JWT instance with the provided options
func New(opts ...JWTOption) *JWT {
	const defaultAlgorithm = HS256

	j := &JWT{
		Algorithm: defaultAlgorithm,
		Payload:   make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(j)
	}

	return j
}

// SetClaim adds a custom claim to the JWT token
func (j *JWT) SetClaim(key string, value interface{}) {
	j.Payload[key] = value
}

// Encode generates the JWT token as a string
func (j *JWT) Encode() (string, error) {
	j.Payload[IssuedAtKey] = time.Now().Unix() // Issued at

	header := map[string]string{
		AlgorithmKey: j.Algorithm,
		TypeKey:      TypeValue,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	encodedHeader := Base64URLEncode(headerJSON)

	claimsJSON, err := json.Marshal(j.Payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	encodedPayload := Base64URLEncode(claimsJSON)

	dataToSign := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	signature, err := j.generateSignature(dataToSign)
	if err != nil {
		return "", fmt.Errorf("failed to generate signature: %w", err)
	}

	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature), nil
}

// generateSignature generates the signature for the given data based on the algorithm
func (j *JWT) generateSignature(data string) (string, error) {
	signatureFuncs := map[string]func(string) (string, error){
		HS256: j.hmacSHA(sha256.New),
		HS384: j.hmacSHA(sha512.New384),
		HS512: j.hmacSHA(sha512.New),
		RS256: j.rsaSign(crypto.SHA256, sha256.New),
		RS384: j.rsaSign(crypto.SHA384, sha512.New384),
		RS512: j.rsaSign(crypto.SHA512, sha512.New),
		ES256: j.ecdsaSign(sha256.New),
		ES384: j.ecdsaSign(sha512.New384),
		ES512: j.ecdsaSign(sha512.New),
		PS256: j.pssSign(crypto.SHA256, sha256.New),
		PS384: j.pssSign(crypto.SHA384, sha512.New384),
		PS512: j.pssSign(crypto.SHA512, sha512.New),
	}

	signFunc, ok := signatureFuncs[j.Algorithm]
	if !ok {
		return "", fmt.Errorf("unsupported algorithm: %s", j.Algorithm)
	}

	return signFunc(data)
}

// hmacSHA generates an HMAC signature using the provided hash function
func (j *JWT) hmacSHA(hashFunc func() hash.Hash) func(string) (string, error) {
	return func(data string) (string, error) {
		h := hmac.New(hashFunc, []byte(j.secretKey))
		h.Write([]byte(data))
		return Base64URLEncode(h.Sum(nil)), nil
	}
}

// rsaSign generates an RSA signature using the provided hash function
func (j *JWT) rsaSign(hash crypto.Hash, hashFunc func() hash.Hash) func(string) (string, error) {
	return func(data string) (string, error) {
		hashed := hashData(data, hashFunc)

		signature, err := rsa.SignPKCS1v15(rand.Reader, j.rsaPrivateKey, hash, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %w", err)
		}

		return Base64URLEncode(signature), nil
	}
}

// ecdsaSign generates an ECDSA signature using the provided hash function
func (j *JWT) ecdsaSign(hashFunc func() hash.Hash) func(string) (string, error) {
	return func(data string) (string, error) {
		hashed := hashData(data, hashFunc)

		r, s, err := ecdsa.Sign(rand.Reader, j.ecdsaPrivateKey, hashed)
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %w", err)
		}

		signature := append(r.Bytes(), s.Bytes()...)
		return Base64URLEncode(signature), nil
	}
}

// pssSign generates an RSA-PSS signature using the provided hash function
func (j *JWT) pssSign(hash crypto.Hash, hashFunc func() hash.Hash) func(string) (string, error) {
	return func(data string) (string, error) {
		hashed := hashData(data, hashFunc)

		signature, err := rsa.SignPSS(rand.Reader, j.rsaPrivateKey, hash, hashed, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return "", fmt.Errorf("failed to sign data: %w", err)
		}
		return Base64URLEncode(signature), nil
	}
}

// DecodeBase64Url decodes a Base64Url-encoded string (like the parts of a JWT)
func DecodeBase64Url(base64Url string) ([]byte, error) {
	base64Url = strings.ReplaceAll(base64Url, "-", "+")
	base64Url = strings.ReplaceAll(base64Url, "_", "/")
	switch len(base64Url) % 4 {
	case 2:
		base64Url += "=="
	case 3:
		base64Url += "="
	}

	return base64.StdEncoding.DecodeString(base64Url)
}

// ParseJWT decodes a JWT token (header and payload) without verification
func ParseJWT(token string) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := DecodeBase64Url(parts[0])
	if err != nil {
		return nil, fmt.Errorf("error decoding header: %w", err)
	}

	payloadBytes, err := DecodeBase64Url(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %w", err)
	}

	signature := parts[2]

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("error unmarshalling header: %w", err)
	}

	typ, ok := header[TypeKey]
	if !ok {
		return nil, fmt.Errorf("missing type in header")
	} else if typ != TypeValue {
		return nil, fmt.Errorf("invalid type in header")
	}

	alg, ok := header[AlgorithmKey]
	if !ok {
		return nil, fmt.Errorf("missing algorithm in header")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("error unmarshalling payload: %w", err)
	}

	return &JWT{
		Algorithm: alg.(string),
		Payload:   payload,
		Signature: signature,
	}, nil
}

// Verify verifies the JWT token signature
func (j *JWT) Verify(token string, publicKey interface{}) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid token format")
	}

	dataToSign := fmt.Sprintf("%s.%s", parts[0], parts[1])
	j.Signature = parts[2]

	signatureFuncs := map[string]func(string, interface{}) (bool, error){
		HS256: j.verifyHMAC(sha256.New),
		HS384: j.verifyHMAC(sha512.New384),
		HS512: j.verifyHMAC(sha512.New),
		RS256: j.verifyRSA(crypto.SHA256, sha256.New),
		RS384: j.verifyRSA(crypto.SHA384, sha512.New384),
		RS512: j.verifyRSA(crypto.SHA512, sha512.New),
		ES256: j.verifyECDSA(sha256.New),
		ES384: j.verifyECDSA(sha512.New384),
		ES512: j.verifyECDSA(sha512.New),
		PS256: j.verifyPSS(crypto.SHA256, sha256.New),
		PS384: j.verifyPSS(crypto.SHA384, sha512.New384),
		PS512: j.verifyPSS(crypto.SHA512, sha512.New),
	}

	verifyFunc, ok := signatureFuncs[j.Algorithm]
	if !ok {
		return false, fmt.Errorf("unsupported algorithm: %s", j.Algorithm)
	}

	return verifyFunc(dataToSign, publicKey)
}

// verifyHMAC verifies an HMAC signature using the provided hash function
func (j *JWT) verifyHMAC(hashFunc func() hash.Hash) func(string, interface{}) (bool, error) {
	return func(data string, _ interface{}) (bool, error) {
		h := hmac.New(hashFunc, []byte(j.secretKey))
		h.Write([]byte(data))
		expectedSignature := Base64URLEncode(h.Sum(nil))

		if subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(j.Signature)) == 1 {
			return true, nil
		}
		return false, fmt.Errorf("invalid signature")
	}
}

// verifyRSA verifies an RSA signature using the provided hash function
func (j *JWT) verifyRSA(hash crypto.Hash, hashFunc func() hash.Hash) func(string, interface{}) (bool, error) {
	return func(data string, publicKey interface{}) (bool, error) {
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("invalid public key type")
		}

		hashed := hashData(data, hashFunc)

		signature, err := base64.RawURLEncoding.DecodeString(j.Signature)
		if err != nil {
			return false, err
		}

		err = rsa.VerifyPKCS1v15(rsaPublicKey, hash, hashed, signature)
		if err != nil {
			return false, err
		}

		return true, nil
	}
}

// verifyECDSA verifies an ECDSA signature using the provided hash function
func (j *JWT) verifyECDSA(hashFunc func() hash.Hash) func(string, interface{}) (bool, error) {
	return func(data string, publicKey interface{}) (bool, error) {
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("invalid public key type")
		}

		signature, err := base64.RawURLEncoding.DecodeString(j.Signature)
		if err != nil {
			return false, err
		}

		signatureLen := len(signature)
		if signatureLen%2 != 0 {
			return false, errors.New("invalid signature length")
		}
		r := new(big.Int).SetBytes(signature[:signatureLen/2])
		s := new(big.Int).SetBytes(signature[signatureLen/2:])

		hashed := hashData(data, hashFunc)

		verified := ecdsa.Verify(ecdsaPublicKey, hashed, r, s)
		if !verified {
			return false, errors.New("signature verification failed")
		}

		return true, nil
	}
}

// verifyPSS verifies an RSA-PSS signature using the provided hash function
func (j *JWT) verifyPSS(hash crypto.Hash, hashFunc func() hash.Hash) func(string, interface{}) (bool, error) {
	return func(data string, publicKey interface{}) (bool, error) {
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("invalid public key type")
		}

		hashed := hashData(data, hashFunc)

		signature, err := base64.RawURLEncoding.DecodeString(j.Signature)
		if err != nil {
			return false, err
		}

		err = rsa.VerifyPSS(rsaPublicKey, hash, hashed, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		if err != nil {
			return false, err
		}

		return true, nil
	}
}
