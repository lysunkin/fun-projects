package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseJWT(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantErr   bool
		wantAlg   string
		wantTyp   string
		wantClaim map[string]interface{}
	}{
		{
			name:    "Valid JWT",
			token:   "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.4f4d5c6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g",
			wantErr: false,
			wantAlg: HS256,
			wantClaim: map[string]interface{}{
				"sub":  "1234567890",
				"name": "John Doe",
				"iat":  float64(1516239022),
			},
		},
		{
			name:    "Invalid JWT format",
			token:   "invalid.jwt.token",
			wantErr: true,
		},
		{
			name:    "Invalid Base64 encoding",
			token:   "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.invalidpayload.4f4d5c6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g",
			wantErr: true,
		},
		{
			name:    "Missing type in header",
			token:   "eyJhbGciOiAiSFMyNTYifQ.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.4f4d5c6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g",
			wantErr: true,
		},
		{
			name:    "Missing algorithm in header",
			token:   "eyJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkpvaG4gRG9lIiwgImlhdCI6IDE1MTYyMzkwMjJ9.4f4d5c6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt, err := ParseJWT(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if jwt.Algorithm != tt.wantAlg {
					t.Errorf("ParseJWT() Algorithm = %v, want %v", jwt.Algorithm, tt.wantAlg)
				}
				for k, v := range tt.wantClaim {
					if jwt.Payload[k] != v {
						t.Errorf("ParseJWT() Claim[%v] = %v, want %v", k, jwt.Payload[k], v)
					}
				}
			}
		})
	}
}

func TestEncodeJWT_HS(t *testing.T) {
	const secretKey = "your-secret-key"
	const claimName = "username"
	const claimValue = "John Doe"

	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{
			name:      "Valid HS256",
			algorithm: "HS256",
		},
		{
			name:      "Valid HS384",
			algorithm: "HS384",
		},
		{
			name:      "Valid HS512",
			algorithm: "HS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwtHS := New(
				WithAlgorithm(tt.algorithm),
				WithSecretKey(secretKey),
				WithExpiry(time.Hour),
			)

			// Set claims
			jwtHS.SetClaim(claimName, claimValue)

			// Encode the token
			tokenHS, err := jwtHS.Encode()
			assert.NoError(t, err)

			// Decode the token
			token, err := ParseJWT(tokenHS)
			assert.NoError(t, err)

			if token.Algorithm != tt.algorithm {
				t.Errorf("Expected algorithm %s, got %s", tt.algorithm, token.Algorithm)
			}

			if token.Payload[claimName] != claimValue {
				t.Errorf("Expected claim %s to be %s, got %s", claimName, claimValue, token.Payload[claimName])
			}
		})
	}
}
