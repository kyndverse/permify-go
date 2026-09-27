package authentication

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Issuer   = "gopher-guard-auth"
	Audience = "gopher-guard"
)

type Claims struct {
	Role string `json:"role"`

	jwt.RegisteredClaims
}

type JWTVerifier struct {
	secret []byte
}

func NewJWTVerifier(secret string) *JWTVerifier {
	return &JWTVerifier{
		secret: []byte(secret),
	}
}

func (v *JWTVerifier) Verify(rawToken string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			return v.secret, nil
		},
		jwt.WithValidMethods(
			[]string{jwt.SigningMethodHS256.Alg()},
		),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to verify token: %w",
			err,
		)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.Subject == "" {
		return nil, errors.New(
			"token subject is required",
		)
	}

	if claims.Role == "" {
		return nil, errors.New(
			"token role is required",
		)
	}

	return claims, nil
}
