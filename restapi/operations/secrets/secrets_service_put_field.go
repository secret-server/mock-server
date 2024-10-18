// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServicePutFieldHandlerFunc turns a function with the right signature into a secrets service put field handler
type SecretsServicePutFieldHandlerFunc func(SecretsServicePutFieldParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServicePutFieldHandlerFunc) Handle(params SecretsServicePutFieldParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServicePutFieldHandler interface for that can handle valid secrets service put field params
type SecretsServicePutFieldHandler interface {
	Handle(SecretsServicePutFieldParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServicePutField creates a new http.Handler for the secrets service put field operation
func NewSecretsServicePutField(ctx *middleware.Context, handler SecretsServicePutFieldHandler) *SecretsServicePutField {
	return &SecretsServicePutField{Context: ctx, Handler: handler}
}

/*
	SecretsServicePutField swagger:route PUT /api/v1/secrets/{id}/fields/{slug} Secrets secretsServicePutField

# Update Secret Field

Update a secret data field
*/
type SecretsServicePutField struct {
	Context *middleware.Context
	Handler SecretsServicePutFieldHandler
}

func (o *SecretsServicePutField) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServicePutFieldParams()
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
