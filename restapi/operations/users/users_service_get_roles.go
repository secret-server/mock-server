// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// UsersServiceGetRolesHandlerFunc turns a function with the right signature into a users service get roles handler
type UsersServiceGetRolesHandlerFunc func(UsersServiceGetRolesParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn UsersServiceGetRolesHandlerFunc) Handle(params UsersServiceGetRolesParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// UsersServiceGetRolesHandler interface for that can handle valid users service get roles params
type UsersServiceGetRolesHandler interface {
    Handle(UsersServiceGetRolesParams, *jwt.MapClaims) middleware.Responder
}

// NewUsersServiceGetRoles creates a new http.Handler for the users service get roles operation
func NewUsersServiceGetRoles(ctx *middleware.Context, handler UsersServiceGetRolesHandler) *UsersServiceGetRoles {
    return &UsersServiceGetRoles{Context: ctx, Handler: handler}
}

/*
    UsersServiceGetRoles swagger:route GET /api/v1/users/{id}/roles Users usersServiceGetRoles

# Gets roles for user

Gets roles for user
*/
type UsersServiceGetRoles struct {
    Context *middleware.Context
    Handler UsersServiceGetRolesHandler
}

func (o *UsersServiceGetRoles) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewUsersServiceGetRolesParams()
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
