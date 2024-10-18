// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceUpdateListFieldListDefinitionsHandlerFunc turns a function with the right signature into a secrets service update list field list definitions handler
type SecretsServiceUpdateListFieldListDefinitionsHandlerFunc func(SecretsServiceUpdateListFieldListDefinitionsParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceUpdateListFieldListDefinitionsHandlerFunc) Handle(params SecretsServiceUpdateListFieldListDefinitionsParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceUpdateListFieldListDefinitionsHandler interface for that can handle valid secrets service update list field list definitions params
type SecretsServiceUpdateListFieldListDefinitionsHandler interface {
	Handle(SecretsServiceUpdateListFieldListDefinitionsParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceUpdateListFieldListDefinitions creates a new http.Handler for the secrets service update list field list definitions operation
func NewSecretsServiceUpdateListFieldListDefinitions(ctx *middleware.Context, handler SecretsServiceUpdateListFieldListDefinitionsHandler) *SecretsServiceUpdateListFieldListDefinitions {
	return &SecretsServiceUpdateListFieldListDefinitions{Context: ctx, Handler: handler}
}

/*
	SecretsServiceUpdateListFieldListDefinitions swagger:route PUT /api/v1/secrets/{id}/fields/{slug}/listdetails Secrets secretsServiceUpdateListFieldListDefinitions

# Update Secret List Field List Data

Updates the lists associated to a secret list data field
*/
type SecretsServiceUpdateListFieldListDefinitions struct {
	Context *middleware.Context
	Handler SecretsServiceUpdateListFieldListDefinitionsHandler
}

func (o *SecretsServiceUpdateListFieldListDefinitions) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceUpdateListFieldListDefinitionsParams()
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