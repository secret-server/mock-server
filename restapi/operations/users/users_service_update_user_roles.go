// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// UsersServiceUpdateUserRolesHandlerFunc turns a function with the right signature into a users service update user roles handler
type UsersServiceUpdateUserRolesHandlerFunc func(UsersServiceUpdateUserRolesParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn UsersServiceUpdateUserRolesHandlerFunc) Handle(params UsersServiceUpdateUserRolesParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// UsersServiceUpdateUserRolesHandler interface for that can handle valid users service update user roles params
type UsersServiceUpdateUserRolesHandler interface {
	Handle(UsersServiceUpdateUserRolesParams, *jwt.MapClaims) middleware.Responder
}

// NewUsersServiceUpdateUserRoles creates a new http.Handler for the users service update user roles operation
func NewUsersServiceUpdateUserRoles(ctx *middleware.Context, handler UsersServiceUpdateUserRolesHandler) *UsersServiceUpdateUserRoles {
	return &UsersServiceUpdateUserRoles{Context: ctx, Handler: handler}
}

/*
	UsersServiceUpdateUserRoles swagger:route PUT /api/v1/users/{id}/roles Users usersServiceUpdateUserRoles

# Update all roles on user

Update all roles on user
*/
type UsersServiceUpdateUserRoles struct {
	Context *middleware.Context
	Handler UsersServiceUpdateUserRolesHandler
}

func (o *UsersServiceUpdateUserRoles) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewUsersServiceUpdateUserRolesParams()
	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		*r = *aCtx
	}
	var principal *jwt.MapClaims
	if uprinc != nil {
		principal = uprinc.(*jwt.MapClaims) // this is really a jwt.MapClaims, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
