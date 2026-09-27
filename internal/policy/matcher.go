package policy

import (
	"fmt"
	"regexp"
	"strings"
)

type Rule struct {
	Method     string
	Path       *regexp.Regexp
	Permission string
}

type Matcher struct {
	rules []Rule
}

func NewMatcher() *Matcher {
	return &Matcher{
		rules: []Rule{
			// Product
			{
				Method:     "GET",
				Path:       regexp.MustCompile(`^/api/products(?:/[^/]+)?$`),
				Permission: "product:read",
			},
			{
				Method:     "POST",
				Path:       regexp.MustCompile(`^/api/products$`),
				Permission: "product:create",
			},
			{
				Method:     "PUT",
				Path:       regexp.MustCompile(`^/api/products/[^/]+$`),
				Permission: "product:update",
			},
			{
				Method:     "PATCH",
				Path:       regexp.MustCompile(`^/api/products/[^/]+$`),
				Permission: "product:update",
			},
			{
				Method:     "DELETE",
				Path:       regexp.MustCompile(`^/api/products/[^/]+$`),
				Permission: "product:delete",
			},

			// Order
			{
				Method:     "GET",
				Path:       regexp.MustCompile(`^/api/orders(?:/[^/]+)?$`),
				Permission: "order:read",
			},
			{
				Method:     "POST",
				Path:       regexp.MustCompile(`^/api/orders$`),
				Permission: "order:create",
			},
			{
				Method:     "POST",
				Path:       regexp.MustCompile(`^/api/orders/[^/]+/cancel$`),
				Permission: "order:cancel",
			},

			// User
			{
				Method:     "GET",
				Path:       regexp.MustCompile(`^/api/users(?:/[^/]+)?$`),
				Permission: "user:read",
			},
			{
				Method:     "PATCH",
				Path:       regexp.MustCompile(`^/api/users/[^/]+$`),
				Permission: "user:update",
			},
		},
	}
}

func (m *Matcher) Resolve(method, path string) (string, error) {
	method = strings.ToUpper(method)

	for _, rule := range m.rules {
		if rule.Method == method && rule.Path.MatchString(path) {
			return rule.Permission, nil
		}
	}

	return "", fmt.Errorf(
		"no authorization policy for %s %s",
		method,
		path,
	)
}
