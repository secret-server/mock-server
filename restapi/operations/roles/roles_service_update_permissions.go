// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// RolesServiceUpdatePermissionsHandlerFunc turns a function with the right signature into a roles service update permissions handler
type RolesServiceUpdatePermissionsHandlerFunc func(RolesServiceUpdatePermissionsParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn RolesServiceUpdatePermissionsHandlerFunc) Handle(params RolesServiceUpdatePermissionsParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// RolesServiceUpdatePermissionsHandler interface for that can handle valid roles service update permissions params
type RolesServiceUpdatePermissionsHandler interface {
    Handle(RolesServiceUpdatePermissionsParams, *jwt.MapClaims) middleware.Responder
}

// NewRolesServiceUpdatePermissions creates a new http.Handler for the roles service update permissions operation
func NewRolesServiceUpdatePermissions(ctx *middleware.Context, handler RolesServiceUpdatePermissionsHandler) *RolesServiceUpdatePermissions {
    return &RolesServiceUpdatePermissions{Context: ctx, Handler: handler}
}

/*
    RolesServiceUpdatePermissions swagger:route PUT /api/v1/roles/{id}/permissions Roles rolesServiceUpdatePermissions

# Update Role Permission Assignments

Update all Permissions assigned to Role
*/
type RolesServiceUpdatePermissions struct {
    Context *middleware.Context
    Handler RolesServiceUpdatePermissionsHandler
}

func (o *RolesServiceUpdatePermissions) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewRolesServiceUpdatePermissionsParams()
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
