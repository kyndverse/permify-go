package authorization

import (
	"fmt"
	"strings"

	"github.com/kyndverse/permify-go/internal/policy"
)

type Service struct {
	rolePermissions map[string]map[string]bool
	policyMatcher   *policy.Matcher
}

func NewService(policyMatcher *policy.Matcher) *Service {
	return &Service{
		policyMatcher: policyMatcher,

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

func (s *Service) Authorize(role string, method string, path string) (bool, string) {
	role = strings.ToUpper(role)

	permission, err := s.policyMatcher.Resolve(method, path)
	if err != nil {
		return false, err.Error()
	}

	permissions, exists := s.rolePermissions[role]
	if !exists {
		return false, fmt.Sprintf(
			"unknown role: %s",
			role,
		)
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
