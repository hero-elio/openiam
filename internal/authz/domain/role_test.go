package domain

import (
	"testing"

	shared "openiam/internal/shared/domain"
)

func TestBuiltinTemplateRoles_HasExpectedDefaults(t *testing.T) {
	roles := BuiltinTemplateRoles()
	if len(roles) != 3 {
		t.Fatalf("unexpected role count: got %d, want 3", len(roles))
	}

	var creatorDefaults int
	for _, role := range roles {
		if !role.IsTemplate {
			t.Fatalf("builtin role should be template: %s", role.Name)
		}
		if !role.IsSystem {
			t.Fatalf("builtin role should be system: %s", role.Name)
		}
		if role.IsDefaultForCreator {
			creatorDefaults++
		}
	}
	if creatorDefaults != 1 {
		t.Fatalf("expected exactly one creator-default role, got %d", creatorDefaults)
	}
}

func TestRole_CloneForAppCopiesPermissionsAndClearsTemplateFlag(t *testing.T) {
	template := &Role{
		Name:                "admin",
		Description:         "admin role",
		Permissions:         []Permission{NewPermission(ResourceUsers, ActionRead)},
		IsSystem:            true,
		IsTemplate:          true,
		IsDefaultForCreator: true,
	}
	appID := shared.NewAppID()
	tenantID := shared.NewTenantID()

	cloned := template.CloneForApp(appID, tenantID)

	if cloned.ID == "" {
		t.Fatal("cloned role id should not be empty")
	}
	if cloned.AppID != appID || cloned.TenantID != tenantID {
		t.Fatalf("clone target mismatch")
	}
	if cloned.Name != template.Name || cloned.Description != template.Description {
		t.Fatalf("clone metadata mismatch")
	}
	if cloned.IsTemplate {
		t.Fatal("runtime cloned role should not keep template flag")
	}
	if !cloned.IsDefaultForCreator {
		t.Fatal("creator default flag should be preserved")
	}
	if len(cloned.Permissions) != 1 || !cloned.HasPermission(NewPermission(ResourceUsers, ActionRead)) {
		t.Fatalf("permissions not copied as expected")
	}

	// ensure permissions were deep-copied.
	template.Permissions[0] = NewPermission(ResourceUsers, ActionDelete)
	if cloned.Permissions[0].Action != ActionRead {
		t.Fatalf("cloned permissions should not track source slice changes")
	}
}
