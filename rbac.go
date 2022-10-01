package rbac

import "strings"

type Effect byte

const (
	Deny Effect = iota
	Allow
)

type RBAC struct {
	rule map[string]Effect
}

func (r RBAC) Authorised(sub, obj, act string) bool {

	if r.rule[r.makeKey(sub, obj, act)] >= 1 {
		return true
	}

	if r.rule[r.makeKey("*", obj, act)] >= 1 {
		return true
	}

	return false
}

func (r RBAC) AddRule(sub, obj, act string, eft Effect) bool {
	r.rule[r.makeKey(sub, obj, act)] = eft
	return true
}

func (r RBAC) makeKey(sub, obj, act string) string {
	return strings.Join([]string{sub, obj, act}, ":")
}

func New() *RBAC {
	return &RBAC{rule: map[string]Effect{}}
}
