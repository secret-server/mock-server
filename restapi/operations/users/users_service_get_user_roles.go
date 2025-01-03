// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// UsersServiceGetUserRolesHandlerFunc turns a function with the right signature into a users service get user roles handler
type UsersServiceGetUserRolesHandlerFunc func(UsersServiceGetUserRolesParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn UsersServiceGetUserRolesHandlerFunc) Handle(params UsersServiceGetUserRolesParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// UsersServiceGetUserRolesHandler interface for that can handle valid users service get user roles params
type UsersServiceGetUserRolesHandler interface {
    Handle(UsersServiceGetUserRolesParams, *jwt.MapClaims) middleware.Responder
}

// NewUsersServiceGetUserRoles creates a new http.Handler for the users service get user roles operation
func NewUsersServiceGetUserRoles(ctx *middleware.Context, handler UsersServiceGetUserRolesHandler) *UsersServiceGetUserRoles {
    return &UsersServiceGetUserRoles{Context: ctx, Handler: handler}
}

/*
    UsersServiceGetUserRoles swagger:route GET /api/v1/users/{userId}/roles-assigned Users usersServiceGetUserRoles

# Get User Roles

Get the roles for a user by ID
*/
type UsersServiceGetUserRoles struct {
    Context *middleware.Context
    Handler UsersServiceGetUserRolesHandler
}

func (o *UsersServiceGetUserRoles) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewUsersServiceGetUserRolesParams()
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
