// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// RolesServiceCreateHandlerFunc turns a function with the right signature into a roles service create handler
type RolesServiceCreateHandlerFunc func(RolesServiceCreateParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn RolesServiceCreateHandlerFunc) Handle(params RolesServiceCreateParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// RolesServiceCreateHandler interface for that can handle valid roles service create params
type RolesServiceCreateHandler interface {
	Handle(RolesServiceCreateParams, *jwt.MapClaims) middleware.Responder
}

// NewRolesServiceCreate creates a new http.Handler for the roles service create operation
func NewRolesServiceCreate(ctx *middleware.Context, handler RolesServiceCreateHandler) *RolesServiceCreate {
	return &RolesServiceCreate{Context: ctx, Handler: handler}
}

/*
	RolesServiceCreate swagger:route POST /api/v1/roles Roles rolesServiceCreate

# Create Role

Create a new Role
*/
type RolesServiceCreate struct {
	Context *middleware.Context
	Handler RolesServiceCreateHandler
}

func (o *RolesServiceCreate) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewRolesServiceCreateParams()
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
