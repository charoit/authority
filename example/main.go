package main

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"authority"
)

type QueryHook struct{}

func (h *QueryHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

func (h *QueryHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	//fmt.Println(event.Query)
}

func main() {
	sqldb := sql.OpenDB(pgdriver.NewConnector(
		pgdriver.WithNetwork("tcp"),
		pgdriver.WithAddr("localhost:5432"),
		pgdriver.WithUser("postgres"),
		pgdriver.WithPassword("postgres"),
		pgdriver.WithDatabase("authority"),
		pgdriver.WithTLSConfig(nil),
	))

	db := bun.NewDB(sqldb, pgdialect.New())
	db.AddQueryHook(&QueryHook{})

	auth := authority.New(authority.Options{
		TablesPrefix: "auth_",
		DB:           db,
	})

	err := auth.CreateRole("role-1")
	fmt.Println(err)

	err = auth.CreatePermission("perm-1")
	fmt.Println(err)
	err = auth.CreatePermission("perm-2")
	fmt.Println(err)

	err = auth.AssignPermissions("role-1", []string{"perm-1", "perm-2"})
	fmt.Println(err)

	err = auth.AssignRole(1, "role-1")
	fmt.Println(err)

	fmt.Println(auth.GetRoles())
	err = auth.DeleteRole("role-1")
	fmt.Println(err)
	fmt.Println(auth.GetRoles())

	//fmt.Println(auth.GetPermissions())
	//fmt.Println(auth.GetUserRoles(1))

}
