// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceGetSecretStateHandlerFunc turns a function with the right signature into a secrets service get secret state handler
type SecretsServiceGetSecretStateHandlerFunc func(SecretsServiceGetSecretStateParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceGetSecretStateHandlerFunc) Handle(params SecretsServiceGetSecretStateParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceGetSecretStateHandler interface for that can handle valid secrets service get secret state params
type SecretsServiceGetSecretStateHandler interface {
	Handle(SecretsServiceGetSecretStateParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceGetSecretState creates a new http.Handler for the secrets service get secret state operation
func NewSecretsServiceGetSecretState(ctx *middleware.Context, handler SecretsServiceGetSecretStateHandler) *SecretsServiceGetSecretState {
	return &SecretsServiceGetSecretState{Context: ctx, Handler: handler}
}

/*
	SecretsServiceGetSecretState swagger:route GET /api/v1/secrets/{id}/state Secrets secretsServiceGetSecretState

# Get Secret State

Retrieve state about a Secret such as whether it requires approval, doublelock, checkout, or other restricted actions to be performed before calling the get the secret.
*/
type SecretsServiceGetSecretState struct {
	Context *middleware.Context
	Handler SecretsServiceGetSecretStateHandler
}

func (o *SecretsServiceGetSecretState) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceGetSecretStateParams()
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