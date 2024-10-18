// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceUpdateExpirationHandlerFunc turns a function with the right signature into a secrets service update expiration handler
type SecretsServiceUpdateExpirationHandlerFunc func(SecretsServiceUpdateExpirationParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceUpdateExpirationHandlerFunc) Handle(params SecretsServiceUpdateExpirationParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceUpdateExpirationHandler interface for that can handle valid secrets service update expiration params
type SecretsServiceUpdateExpirationHandler interface {
	Handle(SecretsServiceUpdateExpirationParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceUpdateExpiration creates a new http.Handler for the secrets service update expiration operation
func NewSecretsServiceUpdateExpiration(ctx *middleware.Context, handler SecretsServiceUpdateExpirationHandler) *SecretsServiceUpdateExpiration {
	return &SecretsServiceUpdateExpiration{Context: ctx, Handler: handler}
}

/*
	SecretsServiceUpdateExpiration swagger:route PUT /api/v1/secrets/{id}/expiration Secrets secretsServiceUpdateExpiration

# Update a Secret expiration

Update a Secret expiration
*/
type SecretsServiceUpdateExpiration struct {
	Context *middleware.Context
	Handler SecretsServiceUpdateExpirationHandler
}

func (o *SecretsServiceUpdateExpiration) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceUpdateExpirationParams()
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
