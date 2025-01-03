// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// RolesServiceUpdateHandlerFunc turns a function with the right signature into a roles service update handler
type RolesServiceUpdateHandlerFunc func(RolesServiceUpdateParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn RolesServiceUpdateHandlerFunc) Handle(params RolesServiceUpdateParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// RolesServiceUpdateHandler interface for that can handle valid roles service update params
type RolesServiceUpdateHandler interface {
    Handle(RolesServiceUpdateParams, *jwt.MapClaims) middleware.Responder
}

// NewRolesServiceUpdate creates a new http.Handler for the roles service update operation
func NewRolesServiceUpdate(ctx *middleware.Context, handler RolesServiceUpdateHandler) *RolesServiceUpdate {
    return &RolesServiceUpdate{Context: ctx, Handler: handler}
}

/*
    RolesServiceUpdate swagger:route PATCH /api/v1/roles/{id} Roles rolesServiceUpdate

# Update Role

Update a single Role by ID
*/
type RolesServiceUpdate struct {
    Context *middleware.Context
    Handler RolesServiceUpdateHandler
}

func (o *RolesServiceUpdate) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewRolesServiceUpdateParams()
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
