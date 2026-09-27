package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/kyndverse/permify-go/internal/authentication"
	"github.com/kyndverse/permify-go/internal/authorization"
	pb "github.com/kyndverse/permify-go/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authorizationServer struct {
	pb.UnimplementedAuthorizationServiceServer

	authService   *authorization.Service
	tokenVerifier *authentication.JWTVerifier
}

func (s *authorizationServer) Check(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	if req.GetAccessToken() == "" {
		return nil, status.Error(
			codes.Unauthenticated,
			"access token is required",
		)
	}

	if req.GetMethod() == "" {
		return nil, status.Error(
			codes.InvalidArgument,
			"method is required",
		)
	}

	if req.GetPath() == "" {
		return nil, status.Error(
			codes.InvalidArgument,
			"path is required",
		)
	}

	claims, err := s.tokenVerifier.Verify(
		req.GetAccessToken(),
	)

	if err != nil {
		log.Printf(
			"token verification failed: %v",
			err,
		)

		return nil, status.Error(
			codes.Unauthenticated,
			"invalid or expired access token",
		)
	}

	log.Printf(
		"authorization check user=%s role=%s method=%s path=%s",
		claims.Subject,
		claims.Role,
		req.GetMethod(),
		req.GetPath(),
	)

	allowed, reason := s.authService.Authorize(
		claims.Role,
		req.GetMethod(),
		req.GetPath(),
	)

	return &pb.CheckResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}

func main() {
	jwtSecret := os.Getenv("JWT_SECRET")

	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	listener, err := net.Listen(
		"tcp",
		":50051",
	)

	if err != nil {
		log.Fatalf(
			"failed to listen: %v",
			err,
		)
	}

	authService := authorization.NewService()

	tokenVerifier :=
		authentication.NewJWTVerifier(jwtSecret)

	grpcServer := grpc.NewServer()

	pb.RegisterAuthorizationServiceServer(
		grpcServer,
		&authorizationServer{
			authService:   authService,
			tokenVerifier: tokenVerifier,
		},
	)

	log.Println(
		"GopherGuard running on :50051",
	)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf(
			"failed to serve: %v",
			err,
		)
	}
}
