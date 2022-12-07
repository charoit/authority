package authority

import "github.com/uptrace/bun"

// Role represents the database model of roles
type Role struct {
	bun.BaseModel `bun:"table:roles,alias:role"`
	ID            uint   `bun:"id,pk,autoincrement"`
	Name          string `bun:"name,unique,notnull"`
	Title         string `bun:"title"`
}

// Permission represents the database model of permissions
type Permission struct {
	bun.BaseModel `bun:"table:permissions,alias:perm"`
	ID            uint   `bun:"id,pk,autoincrement"`
	Name          string `bun:"name,unique,notnull"`
	Title         string `bun:"title"`
}

// RolePermission stores the relationship between roles and permissions
type RolePermission struct {
	bun.BaseModel `bun:"table:role_permissions,alias:rp"`
	ID            uint `bun:"id,pk,autoincrement"`
	RoleID        uint `bun:"role_id,notnull"`
	PermissionID  uint `bun:"permission_id,notnull"`
}

// UserRole represents the relationship between users and roles
type UserRole struct {
	bun.BaseModel `bun:"table:user_roles,alias:ur"`
	ID            uint `bun:"id,pk,autoincrement"`
	UserID        uint `bun:"user_id,notnull"`
	RoleID        uint `bun:"role_id,notnull"`
}
