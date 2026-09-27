package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/kyndverse/permify-go/internal/authentication"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	var userID string
	var role string

	flag.StringVar(
		&userID,
		"user",
		"user-001",
		"user ID",
	)

	flag.StringVar(
		&role,
		"role",
		"USER",
		"user role",
	)

	flag.Parse()

	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	now := time.Now()

	claims := authentication.Claims{
		Role: strings.ToUpper(role),

		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: authentication.Issuer,

			Subject: userID,

			Audience: jwt.ClaimStrings{
				authentication.Audience,
			},

			IssuedAt: jwt.NewNumericDate(now),

			ExpiresAt: jwt.NewNumericDate(
				now.Add(15 * time.Minute),
			),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	tokenString, err := token.SignedString(
		[]byte(secret),
	)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(tokenString)
}
