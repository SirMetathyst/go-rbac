package rbac_test

import (
	"github.com/SirMetathyst/go-rbac"
	"testing"
)

func TestNew(t *testing.T) {
	r := rbac.New()

	if r == nil {
		t.Error("New returned nil")
	}
}

func TestCallingAuthorisedWithoutRulesDefinedReturnsFalse(t *testing.T) {

	r := rbac.New()

	d := []struct {
		sub, obj, act string
	}{
		{"", "", ""},
		{"test", "test", "test"},
	}

	for _, dd := range d {
		if r.Authorised(dd.sub, dd.obj, dd.act) {
			t.Errorf("Authorised(sub: `%s`, obj: `%s`, act: `%s`) returned true when no rules were defined", dd.sub, dd.obj, dd.act)
		}
	}
}

func TestAddRule(t *testing.T) {
	r := rbac.New()

	if !r.AddRule("", "", "", rbac.Allow) {
		t.Error("AddRule returned false")
	}
}

func TestRules(t *testing.T) {

	t.Run("allow single", func(t *testing.T) {

		r := rbac.New()

		r.AddRule("alex", "resource1", "read", rbac.Allow)

		Allowed(t, r, "alex", "resource1", "read")
	})

	t.Run("allow multiple", func(t *testing.T) {

		r := rbac.New()

		r.AddRule("alex", "resource1", "read", rbac.Allow)
		r.AddRule("alex", "resource1", "write", rbac.Allow)
		r.AddRule("alex", "resource2", "read", rbac.Allow)
		r.AddRule("alex", "resource2", "write", rbac.Allow)

		Allowed(t, r, "alex", "resource1", "read")
		Allowed(t, r, "alex", "resource1", "write")
		Allowed(t, r, "alex", "resource2", "read")
		Allowed(t, r, "alex", "resource2", "write")
	})

	t.Run("allow single star", func(t *testing.T) {

		r := rbac.New()

		r.AddRule("*", "resource1", "read", rbac.Allow)

		Allowed(t, r, "alex", "resource1", "read")
	})

	t.Run("allow multiple star", func(t *testing.T) {

		r := rbac.New()

		r.AddRule("*", "resource1", "read", rbac.Allow)
		r.AddRule("*", "resource1", "write", rbac.Allow)
		r.AddRule("*", "resource2", "read", rbac.Allow)
		r.AddRule("*", "resource2", "write", rbac.Allow)

		Allowed(t, r, "alex", "resource1", "read")
		Allowed(t, r, "alex", "resource1", "write")
		Allowed(t, r, "alex", "resource2", "read")
		Allowed(t, r, "alex", "resource2", "write")
	})
}

func Allowed(t *testing.T, r *rbac.RBAC, sub, obj, act string) {
	if !r.Authorised(sub, obj, act) {
		t.Errorf("%s: Authorised(%s,%s,%s) returned false", t.Name(), sub, obj, act)
	}
}
