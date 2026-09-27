package authorization

import (
	"fmt"
	"strings"
)

type Service struct {
	rolePermissions map[string]map[string]bool
}

func NewService() *Service {
	return &Service{
		rolePermissions: map[string]map[string]bool{
			"ADMIN": {
				"product:read":   true,
				"product:create": true,
				"product:update": true,
				"product:delete": true,

				"order:read":   true,
				"order:create": true,
				"order:cancel": true,

				"user:read":   true,
				"user:update": true,
			},

			"USER": {
				"product:read": true,

				"order:read":   true,
				"order:create": true,
			},
		},
	}
}

func (s *Service) Authorize(role, method, path string) (bool, string) {
	role = strings.ToUpper(role)

	permission, err := resolvePermission(method, path)
	if err != nil {
		return false, err.Error()
	}

	permissions, exists := s.rolePermissions[role]
	if !exists {
		return false, fmt.Sprintf("unknown role: %s", role)
	}

	if !permissions[permission] {
		return false, fmt.Sprintf(
			"role %s does not have permission %s",
			role,
			permission,
		)
	}

	return true, fmt.Sprintf(
		"role %s has permission %s",
		role,
		permission,
	)
}

func resolvePermission(method, path string) (string, error) {
	method = strings.ToUpper(method)

	switch {
	case strings.HasPrefix(path, "/api/products"):
		return resolveProductPermission(method)

	case strings.HasPrefix(path, "/api/orders"):
		return resolveOrderPermission(method)

	case strings.HasPrefix(path, "/api/users"):
		return resolveUserPermission(method)

	default:
		return "", fmt.Errorf(
			"no authorization rule for path: %s",
			path,
		)
	}
}

func resolveProductPermission(method string) (string, error) {
	switch method {
	case "GET":
		return "product:read", nil

	case "POST":
		return "product:create", nil

	case "PUT", "PATCH":
		return "product:update", nil

	case "DELETE":
		return "product:delete", nil

	default:
		return "", fmt.Errorf(
			"unsupported method %s for products",
			method,
		)
	}
}

func resolveOrderPermission(method string) (string, error) {
	switch method {
	case "GET":
		return "order:read", nil

	case "POST":
		return "order:create", nil

	case "DELETE":
		return "order:cancel", nil

	default:
		return "", fmt.Errorf(
			"unsupported method %s for orders",
			method,
		)
	}
}

func resolveUserPermission(method string) (string, error) {
	switch method {
	case "GET":
		return "user:read", nil

	case "PUT", "PATCH":
		return "user:update", nil

	default:
		return "", fmt.Errorf(
			"unsupported method %s for users",
			method,
		)
	}
}
