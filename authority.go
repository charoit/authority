package authority

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
)

// Authority helps deal with permissions
type Authority struct {
	DB *bun.DB

	TableRole     string
	TablePerm     string
	TableRolePerm string
	TableUserRole string
}

// Options has the options for initiating the package
type Options struct {
	DB           *bun.DB
	TablesPrefix string
}

var (
	ErrPermissionInUse        = errors.New("cannot delete assigned permission")
	ErrPermissionNotFound     = errors.New("permission not found")
	ErrRoleAlreadyAssigned    = errors.New("this role is already assigned to the user")
	ErrRoleInUse              = errors.New("cannot delete assigned role")
	ErrRoleNotFound           = errors.New("role not found")
	ErrRolePermissionNotFound = errors.New("permission for a role not found")
	ErrUserRoleNotFound       = errors.New("role for a user not found")
	ErrRoleExists             = errors.New("role exists")
)

var auth *Authority

// New initiates authority
func New(opts Options) *Authority {
	auth = &Authority{
		DB:            opts.DB,
		TableRole:     opts.TablesPrefix + "roles AS role",
		TablePerm:     opts.TablesPrefix + "permissions AS perm",
		TableRolePerm: opts.TablesPrefix + "role_permissions AS rp",
		TableUserRole: opts.TablesPrefix + "user_roles AS ur",
	}

	if err := migrateTables(&opts); err != nil {
		panic(err)
	}

	return auth
}

// Resolve returns the initiated instance
func Resolve() *Authority {
	return auth
}

// CreateRole stores a role in the database it accepts the role name.
// it returns an error in case of any
func (a *Authority) CreateRole(roleName string) error {
	var err error
	ctx := context.Background()

	var exists bool
	if exists, err = a.DB.NewSelect().Model((*Role)(nil)).ModelTableExpr(a.TableRole).
		Where("name = ?", roleName).Exists(ctx); err != nil {
		return err
	}

	if !exists {
		if _, err = a.DB.NewInsert().Model(&Role{Name: roleName}).ModelTableExpr(a.TableRole).Exec(ctx); err != nil {
			return err
		}
	}

	return nil
}

// CreatePermission stores a permission in the database it accepts the permission name.
// it returns an error in case of any
func (a *Authority) CreatePermission(permName string) error {
	var err error
	ctx := context.Background()

	var exists bool
	if exists, err = a.DB.NewSelect().Model((*Permission)(nil)).ModelTableExpr(a.TablePerm).
		Where("name = ?", permName).Exists(ctx); err != nil {
		return err
	}

	if !exists {
		if _, err = a.DB.NewInsert().Model(&Permission{Name: permName}).ModelTableExpr(a.TablePerm).Exec(ctx); err != nil {
			return err
		}
	}

	return nil
}

// AssignPermissions assigns a group of permissions to a given role it accepts in the first parameter the role name,
// it returns an error if there is not matching record of the role name in the database.
// the second parameter is a slice of strings which represents a group of permissions to be assigned to the role
// if any of these permissions doesn't have a matching record in the database the operations stops, changes reverted
// and error is returned in case of success nothing is returned
func (a *Authority) AssignPermissions(roleName string, permNames []string) error {
	var err error
	ctx := context.Background()

	// get the role id
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return err
	}

	var perms []*Permission
	for _, permName := range permNames {
		var perm *Permission
		if perm, err = a.getPermission(permName); err != nil {
			return err
		}
		perms = append(perms, perm)
	}

	// insert data into RolePermissions table
	for _, perm := range perms {
		// ignore any assigned permission
		if _, err = a.getRolePermission(role.ID, perm.ID); err != nil {
			// assign the record
			if _, err = a.DB.NewInsert().Model(&RolePermission{RoleID: role.ID, PermissionID: perm.ID}).
				ModelTableExpr(a.TableRolePerm).Exec(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

// AssignRole assigns a given role to a user the first parameter is the user id, the second parameter is the role name
// if the role name doesn't have a matching record in the data base an error is returned
// if the user have already a role assigned to him an error is returned
func (a *Authority) AssignRole(userID uint, roleName string) error {
	var err error
	ctx := context.Background()

	// make sure the role exist
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return err
	}

	// check if the role is already assigned
	if _, err = a.getUserRole(userID, role.ID); err == nil {
		//found a record, this role is already assigned to the same user
		return ErrRoleAlreadyAssigned
	}

	// assign the role
	_, err = a.DB.NewInsert().Model(&UserRole{UserID: userID, RoleID: role.ID}).ModelTableExpr(a.TableUserRole).Exec(ctx)

	return err
}

// CheckRole checks if a role is assigned to a user
// it accepts the user id as the first parameter
// the role as the second parameter
// it returns an error if the role is not present in database
func (a *Authority) CheckRole(userID uint, roleName string) (bool, error) {
	var err error

	// find the role
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return false, err
	}

	// check if the role is assigned
	if _, err = a.getUserRole(userID, role.ID); err != nil {
		if errors.Is(err, ErrUserRoleNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// CheckPermission checks if a permission is assigned to the role that's assigned to the user.
// it accepts the user id as the first parameter the permission as the second parameter
// it returns an error if the permission is not present in the database
func (a *Authority) CheckPermission(userID uint, permName string) (bool, error) {
	var err error
	ctx := context.Background()
	// the user role
	var userRoles []UserRole
	if err = a.DB.NewSelect().Model(&userRoles).ModelTableExpr(a.TableUserRole).
		Where("user_id = ?", userID).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, err
	}

	//prepare an array of role ids
	var roleIDs []uint
	for _, r := range userRoles {
		roleIDs = append(roleIDs, r.RoleID)
	}

	// find the permission
	var perm *Permission
	if perm, err = a.getPermission(permName); err != nil {
		return false, err
	}

	// find the role permission
	var rolePermission RolePermission
	if err = a.DB.NewSelect().Model(&rolePermission).ModelTableExpr(a.TableRolePerm).
		Where("role_id IN (?)", bun.In(roleIDs)).Where("permission_id = ?", perm.ID).
		Scan(ctx); err != nil {
		return false, nil
	}

	return true, nil
}

// CheckRolePermission checks if a role has the permission assigned it accepts the role as the first parameter
// it accepts the permission as the second parameter it returns an error if the role is not present in database
// it returns an error if the permission is not present in database
func (a *Authority) CheckRolePermission(roleName string, permName string) (bool, error) {
	var err error

	// find the role
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return false, err
	}

	// find the permission
	var perm *Permission
	if perm, err = a.getPermission(permName); err != nil {
		return false, err
	}

	// find the rolePermission
	if _, err = a.getRolePermission(role.ID, perm.ID); err != nil {
		if errors.Is(err, ErrRolePermissionNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// RevokeRole revokes a user's role
// it returns a error in case of any
func (a *Authority) RevokeRole(userID uint, roleName string) error {
	var err error
	ctx := context.Background()

	// find the role
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return err
	}

	// revoke the role
	_, err = a.DB.NewDelete().Model((*UserRole)(nil)).ModelTableExpr(a.TableUserRole).
		Where("user_id = ?", userID).Where("role_id = ?", role.ID).Exec(ctx)

	return err
}

// RevokePermission revokes a permission from the user's assigned role
// it returns an error in case of any
func (a *Authority) RevokePermission(userID uint, permName string) error {
	var err error
	ctx := context.Background()
	// revoke the permission from all roles of the user find the user roles
	var userRoles []UserRole
	if err = a.DB.NewSelect().Model(&userRoles).ModelTableExpr(a.TableUserRole).
		Where("user_id = ?", userID).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}

		return err
	}

	// find the permission
	var perm *Permission
	if perm, err = a.getPermission(permName); err != nil {
		return err
	}

	for _, r := range userRoles {
		// revoke the permission
		if _, err = a.DB.NewDelete().Model((*RolePermission)(nil)).ModelTableExpr(a.TableRolePerm).
			Where("role_id = ?", r.RoleID).Where("permission_id = ?", perm.ID).Exec(ctx); err != nil {
			return err
		}
	}

	return nil
}

// RevokeRolePermission revokes a permission from a given role
// it returns an error in case of any
func (a *Authority) RevokeRolePermission(roleName string, permName string) error {
	var err error
	ctx := context.Background()

	// find the role
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return err
	}

	// find the permission
	var perm *Permission
	if perm, err = a.getPermission(permName); err != nil {
		return err
	}

	// revoke the permission
	_, err = a.DB.NewDelete().Model((*RolePermission)(nil)).ModelTableExpr(a.TableRolePerm).
		Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).Exec(ctx)

	return nil
}

// GetRoles returns all stored roles
func (a *Authority) GetRoles() ([]string, error) {
	var roles []Role
	if err := a.DB.NewSelect().Model(&roles).ModelTableExpr(a.TableRole).Scan(context.Background()); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(roles))
	for _, role := range roles {
		result = append(result, role.Name)
	}

	return result, nil
}

// GetUserRoles returns all user assigned roles
func (a *Authority) GetUserRoles(userID uint) ([]string, error) {
	ctx := context.Background()
	var userRoles []UserRole
	if err := a.DB.NewSelect().Model(&userRoles).ModelTableExpr(a.TableUserRole).
		Where("user_id = ?", userID).Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(userRoles))
	for _, r := range userRoles {
		var role Role
		// for every user role get the role name
		if err := a.DB.NewSelect().Model(&role).ModelTableExpr(a.TableRole).
			Where("id = ?", r.RoleID).Scan(ctx); err == nil {
			result = append(result, role.Name)
		}
	}

	return result, nil
}

// GetPermissions returns all stored permissions
func (a *Authority) GetPermissions() ([]string, error) {
	var perms []Permission
	if err := a.DB.NewSelect().Model(&perms).ModelTableExpr(a.TablePerm).
		Scan(context.Background()); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(perms))
	for _, perm := range perms {
		result = append(result, perm.Name)
	}

	return result, nil
}

// DeleteRole deletes a given role
// if the role is assigned to a user it returns an error
func (a *Authority) DeleteRole(roleName string) error {
	var err error
	ctx := context.Background()

	// find the role
	var role *Role
	if role, err = a.getRole(roleName); err != nil {
		return err
	}

	// check if the role is assigned to a user
	var userRole UserRole
	if err = a.DB.NewSelect().Model(&userRole).ModelTableExpr(a.TableUserRole).
		Where("role_id = ?", role.ID).Scan(ctx); err == nil {
		// role is assigned
		return ErrRoleInUse
	}

	// revoke the assignment of permissions before deleting the role
	if _, err = a.DB.NewSelect().Model((*RolePermission)(nil)).ModelTableExpr(a.TableRolePerm).
		Where("role_id = ?", role.ID).Exec(ctx); err != nil {
		return err
	}

	// delete the role
	if _, err = a.DB.NewDelete().Model((*Role)(nil)).ModelTableExpr(a.TableRole).
		Where("name = ?", roleName).Exec(ctx); err != nil {
		return err
	}

	return nil
}

// DeletePermission deletes a given permission
// if the permission is assigned to a role it returns an error
func (a *Authority) DeletePermission(permName string) error {
	var err error
	ctx := context.Background()

	// find the permission
	var perm *Permission
	if perm, err = a.getPermission(permName); err != nil {
		return err
	}

	// check if the permission is assigned to a role
	var rolePermission RolePermission
	if err = a.DB.NewSelect().Model(&rolePermission).ModelTableExpr(a.TableRolePerm).
		Where("permission_id = ?", perm.ID).Scan(ctx); err == nil {
		// role is assigned
		return ErrPermissionInUse
	}

	// delete the permission
	if _, err = a.DB.NewDelete().Model((*Permission)(nil)).ModelTableExpr(a.TablePerm).
		Where("name = ?", permName).Exec(ctx); err != nil {
		return err
	}

	return nil
}

func (a *Authority) getRole(roleName string) (*Role, error) {
	ctx := context.Background()
	var role Role
	if err := a.DB.NewSelect().Model(&role).Where("name = ?", roleName).ModelTableExpr(a.TableRole).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
	}

	return &role, nil
}

func (a *Authority) getPermission(permName string) (*Permission, error) {
	ctx := context.Background()
	var perm Permission
	if err := a.DB.NewSelect().Model(&perm).Where("name = ?", permName).
		ModelTableExpr(a.TablePerm).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPermissionNotFound
		}
	}

	return &perm, nil
}

func (a *Authority) getRolePermission(roleID, permID uint) (*RolePermission, error) {
	var rolePerm RolePermission
	if err := a.DB.NewSelect().Model(&rolePerm).ModelTableExpr(a.TableRolePerm).
		Where("role_id = ?", roleID).Where("permission_id =?", permID).
		Scan(context.Background()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRolePermissionNotFound
		}

		return nil, err
	}

	return &rolePerm, nil
}

func (a *Authority) getUserRole(userID, roleID uint) (*UserRole, error) {
	var userRole UserRole
	if err := a.DB.NewSelect().Model(&userRole).ModelTableExpr(a.TableUserRole).
		Where("user_id = ?", userID).Where("role_id = ?", roleID).
		Scan(context.Background()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserRoleNotFound
		}
		return nil, err
	}

	return &userRole, nil
}

func migrateTables(opts *Options) error {
	ctx := context.Background()

	if _, err := opts.DB.NewCreateTable().IfNotExists().Model((*Role)(nil)).
		ModelTableExpr(opts.TablesPrefix + "roles").Exec(ctx); err != nil {
		return err
	}

	if _, err := opts.DB.NewCreateTable().IfNotExists().Model((*Permission)(nil)).
		ModelTableExpr(opts.TablesPrefix + "permissions").Exec(ctx); err != nil {
		return err
	}

	roleFk1 := fmt.Sprintf(`("role_id") REFERENCES "%s" ("id") ON DELETE CASCADE`, opts.TablesPrefix+"roles")
	roleFk2 := fmt.Sprintf(`("permission_id") REFERENCES "%s" ("id") ON DELETE CASCADE`, opts.TablesPrefix+"permissions")
	if _, err := opts.DB.NewCreateTable().IfNotExists().Model((*RolePermission)(nil)).
		ModelTableExpr(opts.TablesPrefix + "role_permissions").
		ForeignKey(roleFk1).ForeignKey(roleFk2).Exec(ctx); err != nil {
		return err
	}

	userFk1 := fmt.Sprintf(`("role_id") REFERENCES "%s" ("id") ON DELETE CASCADE`, opts.TablesPrefix+"roles")
	if _, err := opts.DB.NewCreateTable().IfNotExists().Model((*UserRole)(nil)).
		ModelTableExpr(opts.TablesPrefix + "user_roles").
		ForeignKey(userFk1).Exec(ctx); err != nil {
		return err
	}

	return nil
}
