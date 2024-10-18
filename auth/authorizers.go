package auth

import (
	"time"

	errors "github.com/go-openapi/errors"
	"github.com/golang-jwt/jwt"
)

const (
	// currently unused: privateKeyPath = "keys/apiKey.prv"
	publicKeyPath = "keys/apiKey.pem"
	issuerName    = "example.com"
)

var secretKey = []byte("mock-secret-key")

// GenerateJWT generates a JWT token for the user
// Reference:
// https://shashankvivek-7.medium.com/go-swagger-user-authentication-securing-api-using-jwt-part-1-6e2a0ab8c721
// https://medium.com/@cheickzida/golang-implementing-jwt-token-authentication-bba9bfd84d60
// https://permify.co/post/jwt-authentication-go/
func CreateToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, 
		jwt.MapClaims{ 
			"authorized": true,
			"username": username, 
			"exp": time.Now().Add(time.Hour * 24).Unix(), 
		})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}


func ParseAndCheckToken(token string) (jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token, func(parsedToken *jwt.Token) (interface{}, error) {
		// the key used to validate tokens
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, errors.New(502,"Invalid token or missing expected claims")
	}

	return claims, nil
}
