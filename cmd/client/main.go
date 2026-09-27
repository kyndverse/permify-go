package main

import (
	"context"
	"log"
	"os"
	"time"

	pb "github.com/kyndverse/permify-go/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	accessToken := os.Getenv("ACCESS_TOKEN")

	if accessToken == "" {
		log.Fatal("ACCESS_TOKEN is required")
	}

	conn, err := grpc.NewClient(
		"127.0.0.1:50051",
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
	)

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	client :=
		pb.NewAuthorizationServiceClient(conn)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancel()

	response, err := client.Check(
		ctx,
		&pb.CheckRequest{
			AccessToken: accessToken,
			Method:      "GET",
			Path:        "/api/products",
		},
	)

	if err != nil {
		log.Fatalf(
			"authorization failed: %v",
			err,
		)
	}

	log.Printf(
		"allowed=%t reason=%s",
		response.GetAllowed(),
		response.GetReason(),
	)
}
