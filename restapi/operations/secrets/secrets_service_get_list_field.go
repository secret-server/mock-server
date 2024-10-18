// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceGetListFieldHandlerFunc turns a function with the right signature into a secrets service get list field handler
type SecretsServiceGetListFieldHandlerFunc func(SecretsServiceGetListFieldParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceGetListFieldHandlerFunc) Handle(params SecretsServiceGetListFieldParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceGetListFieldHandler interface for that can handle valid secrets service get list field params
type SecretsServiceGetListFieldHandler interface {
	Handle(SecretsServiceGetListFieldParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceGetListField creates a new http.Handler for the secrets service get list field operation
func NewSecretsServiceGetListField(ctx *middleware.Context, handler SecretsServiceGetListFieldHandler) *SecretsServiceGetListField {
	return &SecretsServiceGetListField{Context: ctx, Handler: handler}
}

/*
	SecretsServiceGetListField swagger:route GET /api/v1/secrets/{id}/fields/{slug}/list Secrets secretsServiceGetListField

# Get Secret List Field

Get the items associated to a secret list data field
*/
type SecretsServiceGetListField struct {
	Context *middleware.Context
	Handler SecretsServiceGetListFieldHandler
}

func (o *SecretsServiceGetListField) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceGetListFieldParams()
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
