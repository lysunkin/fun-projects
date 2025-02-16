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
	"fmt"
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

// New now takes a slice of option as the rest arguments
func New(opts ...JWTOption) *JWT {
	const (
		defaultAlgorithm = HS256
	)

	j := &JWT{
		Algorithm: defaultAlgorithm,
		Payload:   make(map[string]interface{}),
	}

	// Loop through each option
	for _, opt := range opts {
		// Call the option giving the instantiated
		// *JWT as the argument
		opt(j)
	}

	// return the modified JWT instance
	return j
}

// SetClaim adds a custom claim to the JWT token
func (j *JWT) SetClaim(key string, value interface{}) {
	j.Payload[key] = value
}

// Encode generates the JWT token as a string
func (j *JWT) Encode() (string, error) {
	// Set the standard claims
	j.Payload[IssuedAtKey] = time.Now().Unix() // Issued at

	// Encode the header (metadata)
	header := map[string]string{
		AlgorithmKey: j.Algorithm,
		TypeKey:      TypeValue,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	encodedHeader := Base64URLEncode(headerJSON)

	// Encode the payload (claims)
	claimsJSON, err := json.Marshal(j.Payload)
	if err != nil {
		return "", err
	}
	encodedPayload := Base64URLEncode(claimsJSON)

	// Generate the signature
	dataToSign := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	signature, err := j.generateSignature(dataToSign)
	if err != nil {
		return "", err
	}

	// Return the final JWT token
	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature), nil
}

// generateSignature generates the signature for the given data based on the algorithm
func (j *JWT) generateSignature(data string) (string, error) {
	signatureFuncs := map[string]func(string) (string, error){
		HS256: j.hmacSHA256,
		HS384: j.hmacSHA384,
		HS512: j.hmacSHA512,
		RS256: j.RS256,
		RS384: j.RS384,
		RS512: j.RS512,
		ES256: j.ES256,
		ES384: j.ES384,
		ES512: j.ES512,
		PS256: j.PS256,
		PS384: j.PS384,
		PS512: j.PS512,
	}

	signFunc, ok := signatureFuncs[j.Algorithm]
	if !ok {
		return "", fmt.Errorf("unsupported algorithm: %s", j.Algorithm)
	}

	return signFunc(data)
}

// hmacSHA256 generates an HMAC SHA-256 signature
func (j *JWT) hmacSHA256(data string) (string, error) {
	h := hmac.New(sha512.New512_256, []byte(j.secretKey))
	h.Write([]byte(data))
	return Base64URLEncode(h.Sum(nil)), nil
}

// hmacSHA384 generates an HMAC SHA-384 signature
func (j *JWT) hmacSHA384(data string) (string, error) {
	h := hmac.New(sha512.New384, []byte(j.secretKey))
	h.Write([]byte(data))
	return Base64URLEncode(h.Sum(nil)), nil
}

// hmacSHA512 generates an HMAC SHA-512 signature
func (j *JWT) hmacSHA512(data string) (string, error) {
	h := hmac.New(sha512.New, []byte(j.secretKey))
	h.Write([]byte(data))
	return Base64URLEncode(h.Sum(nil)), nil
}

func (j *JWT) RS256(data string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, j.rsaPrivateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}

	return Base64URLEncode(signature), nil
}

func (j *JWT) RS384(data string) (string, error) {
	hasher := sha512.New384()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, j.rsaPrivateKey, crypto.SHA384, hashed)
	if err != nil {
		return "", err
	}

	return Base64URLEncode(signature), nil
}

func (j *JWT) RS512(data string) (string, error) {
	hasher := sha512.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, j.rsaPrivateKey, crypto.SHA512, hashed)
	if err != nil {
		return "", err
	}

	return Base64URLEncode(signature), nil
}

func (j *JWT) ES256(data string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, j.ecdsaPrivateKey, hashed)
	if err != nil {
		return "", err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return Base64URLEncode(signature), nil
}

func (j *JWT) ES384(data string) (string, error) {
	hasher := sha512.New384()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, j.ecdsaPrivateKey, hashed)
	if err != nil {
		return "", err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return Base64URLEncode(signature), nil
}

func (j *JWT) ES512(data string) (string, error) {
	hasher := sha512.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, j.ecdsaPrivateKey, hashed)
	if err != nil {
		return "", err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return Base64URLEncode(signature), nil
}

func (j *JWT) PS256(data string) (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	// Use rsa.SignPSS for PS256
	signature, err := rsa.SignPSS(rand.Reader, j.rsaPrivateKey, crypto.SHA256, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // Use salt length equal to hash length
	})
	if err != nil {
		return "", err
	}
	return Base64URLEncode(signature), nil
}

func (j *JWT) PS384(data string) (string, error) {
	hasher := sha512.New384()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, j.rsaPrivateKey, crypto.SHA384, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // Use salt length equal to hash length
	})
	if err != nil {
		return "", err
	}
	return Base64URLEncode(signature), nil
}

func (j *JWT) PS512(data string) (string, error) {
	hasher := sha512.New()
	hasher.Write([]byte(data))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, j.rsaPrivateKey, crypto.SHA512, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, // Use salt length equal to hash length
	})
	if err != nil {
		return "", err
	}
	return Base64URLEncode(signature), nil
}

// DecodeBase64Url decodes a Base64Url-encoded string (like the parts of a JWT)
func DecodeBase64Url(base64Url string) ([]byte, error) {
	// Base64Url replaces `+` and `/` with `-` and `_`, respectively.
	// Add padding if needed
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

	// Decode Header
	headerBytes, err := DecodeBase64Url(parts[0])
	if err != nil {
		return nil, fmt.Errorf("error decoding header: %v", err)
	}

	// Decode Payload
	payloadBytes, err := DecodeBase64Url(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding payload: %v", err)
	}

	// Decode Signature (no need to decode to JSON)
	signature := parts[2]

	// Unmarshal JSON to struct for easier handling
	var header map[string]interface{}
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling header: %v", err)
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
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling payload: %v", err)
	}

	return &JWT{
		Algorithm: alg.(string),
		Payload:   payload,
		Signature: string(signature),
	}, nil
}

// Verify verifies the JWT token signature
func (j *JWT) Verify(token string) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid token format")
	}

	dataToSign := fmt.Sprintf("%s.%s", parts[0], parts[1])
	expectedSignature := parts[2]

	signature, err := j.generateSignature(dataToSign)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSignature)) == 1 {
		return true, nil
	}
	return false, fmt.Errorf("invalid signature")
}
