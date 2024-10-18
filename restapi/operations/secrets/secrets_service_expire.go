// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceExpireHandlerFunc turns a function with the right signature into a secrets service expire handler
type SecretsServiceExpireHandlerFunc func(SecretsServiceExpireParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceExpireHandlerFunc) Handle(params SecretsServiceExpireParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceExpireHandler interface for that can handle valid secrets service expire params
type SecretsServiceExpireHandler interface {
	Handle(SecretsServiceExpireParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceExpire creates a new http.Handler for the secrets service expire operation
func NewSecretsServiceExpire(ctx *middleware.Context, handler SecretsServiceExpireHandler) *SecretsServiceExpire {
	return &SecretsServiceExpire{Context: ctx, Handler: handler}
}

/*
	SecretsServiceExpire swagger:route POST /api/v1/secrets/{id}/expire Secrets secretsServiceExpire

# Expire Secret

Expire a secret
*/
type SecretsServiceExpire struct {
	Context *middleware.Context
	Handler SecretsServiceExpireHandler
}

func (o *SecretsServiceExpire) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceExpireParams()
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