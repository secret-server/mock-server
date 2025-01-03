// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// UsersServiceUpdateUserHandlerFunc turns a function with the right signature into a users service update user handler
type UsersServiceUpdateUserHandlerFunc func(UsersServiceUpdateUserParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn UsersServiceUpdateUserHandlerFunc) Handle(params UsersServiceUpdateUserParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// UsersServiceUpdateUserHandler interface for that can handle valid users service update user params
type UsersServiceUpdateUserHandler interface {
    Handle(UsersServiceUpdateUserParams, *jwt.MapClaims) middleware.Responder
}

// NewUsersServiceUpdateUser creates a new http.Handler for the users service update user operation
func NewUsersServiceUpdateUser(ctx *middleware.Context, handler UsersServiceUpdateUserHandler) *UsersServiceUpdateUser {
    return &UsersServiceUpdateUser{Context: ctx, Handler: handler}
}

/*
    UsersServiceUpdateUser swagger:route PUT /api/v1/users/{id} Users usersServiceUpdateUser

# Update User

Update a single user by ID
*/
type UsersServiceUpdateUser struct {
    Context *middleware.Context
    Handler UsersServiceUpdateUserHandler
}

func (o *UsersServiceUpdateUser) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewUsersServiceUpdateUserParams()
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
