// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// RolesServiceStubHandlerFunc turns a function with the right signature into a roles service stub handler
type RolesServiceStubHandlerFunc func(RolesServiceStubParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn RolesServiceStubHandlerFunc) Handle(params RolesServiceStubParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// RolesServiceStubHandler interface for that can handle valid roles service stub params
type RolesServiceStubHandler interface {
    Handle(RolesServiceStubParams, *jwt.MapClaims) middleware.Responder
}

// NewRolesServiceStub creates a new http.Handler for the roles service stub operation
func NewRolesServiceStub(ctx *middleware.Context, handler RolesServiceStubHandler) *RolesServiceStub {
    return &RolesServiceStub{Context: ctx, Handler: handler}
}

/*
    RolesServiceStub swagger:route GET /api/v1/roles/stub Roles rolesServiceStub

# Get Role Stub

Return the default values for a new Role
*/
type RolesServiceStub struct {
    Context *middleware.Context
    Handler RolesServiceStubHandler
}

func (o *RolesServiceStub) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewRolesServiceStubParams()
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
