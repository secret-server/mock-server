// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceUpdateSecretHandlerFunc turns a function with the right signature into a secrets service update secret handler
type SecretsServiceUpdateSecretHandlerFunc func(SecretsServiceUpdateSecretParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceUpdateSecretHandlerFunc) Handle(params SecretsServiceUpdateSecretParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceUpdateSecretHandler interface for that can handle valid secrets service update secret params
type SecretsServiceUpdateSecretHandler interface {
	Handle(SecretsServiceUpdateSecretParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceUpdateSecret creates a new http.Handler for the secrets service update secret operation
func NewSecretsServiceUpdateSecret(ctx *middleware.Context, handler SecretsServiceUpdateSecretHandler) *SecretsServiceUpdateSecret {
	return &SecretsServiceUpdateSecret{Context: ctx, Handler: handler}
}

/*
	SecretsServiceUpdateSecret swagger:route PUT /api/v1/secrets/{id} Secrets secretsServiceUpdateSecret

# Update Secret

Update a single secret by ID
*/
type SecretsServiceUpdateSecret struct {
	Context *middleware.Context
	Handler SecretsServiceUpdateSecretHandler
}

func (o *SecretsServiceUpdateSecret) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceUpdateSecretParams()
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