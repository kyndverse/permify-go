package main

import (
	"context"
	"log"
	"net"
	"os"
	"strings"

	"github.com/kyndverse/permify-go/internal/authentication"
	"github.com/kyndverse/permify-go/internal/authorization"
	"github.com/kyndverse/permify-go/internal/policy"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authorizationServer struct {
	authv3.UnimplementedAuthorizationServer

	authService   *authorization.Service
	tokenVerifier *authentication.JWTVerifier
}

func (s *authorizationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpRequest := req.GetAttributes().
		GetRequest().
		GetHttp()

	if httpRequest == nil {
		return deny(
			codes.InvalidArgument,
			typev3.StatusCode_BadRequest,
			"missing HTTP request information",
		), nil
	}

	method := httpRequest.GetMethod()
	path := httpRequest.GetPath()

	authHeader := httpRequest.
		GetHeaders()["authorization"]

	log.Printf(
		"authorization check method=%s path=%s",
		method,
		path,
	)

	token, ok := extractBearerToken(authHeader)
	if !ok {
		return deny(
			codes.Unauthenticated,
			typev3.StatusCode_Unauthorized,
			"missing or invalid Authorization header",
		), nil
	}

	claims, err := s.tokenVerifier.Verify(token)
	if err != nil {
		log.Printf("JWT verification failed: %v", err)

		return deny(
			codes.Unauthenticated,
			typev3.StatusCode_Unauthorized,
			"invalid or expired access token",
		), nil
	}

	allowed, reason := s.authService.Authorize(
		claims.Role,
		method,
		path,
	)

	log.Printf(
		"user=%s role=%s permission_result=%t reason=%s",
		claims.Subject,
		claims.Role,
		allowed,
		reason,
	)

	if !allowed {
		return deny(
			codes.PermissionDenied,
			typev3.StatusCode_Forbidden,
			reason,
		), nil
	}

	return allow(
		claims.Subject,
		claims.Role,
	), nil
}

func extractBearerToken(header string) (string, bool) {
	parts := strings.SplitN(header, " ", 2)

	if len(parts) != 2 {
		return "", false
	}

	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(parts[1])

	if token == "" {
		return "", false
	}

	return token, true
}

func allow(userID string, role string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: status.New(
			codes.OK,
			"authorized",
		).Proto(),

		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "x-current-user",
							Value: userID,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "x-current-role",
							Value: role,
						},
					},
				},
			},
		},
	}
}

func deny(grpcCode codes.Code, httpCode typev3.StatusCode, message string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: status.New(
			grpcCode,
			message,
		).Proto(),

		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: httpCode,
				},
				Body: message,
			},
		},
	}
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

	policyMatcher := policy.NewMatcher()
	authService := authorization.NewService(policyMatcher)
	tokenVerifier := authentication.NewJWTVerifier(jwtSecret)

	grpcServer := grpc.NewServer()

	authv3.RegisterAuthorizationServer(
		grpcServer,
		&authorizationServer{
			authService:   authService,
			tokenVerifier: tokenVerifier,
		},
	)

	log.Println(
		"Permify-go ext_authz server running on :50051",
	)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf(
			"failed to serve: %v",
			err,
		)
	}
}
