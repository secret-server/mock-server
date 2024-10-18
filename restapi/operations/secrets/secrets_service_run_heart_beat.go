// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	"github.com/golang-jwt/jwt"
)

// SecretsServiceRunHeartBeatHandlerFunc turns a function with the right signature into a secrets service run heart beat handler
type SecretsServiceRunHeartBeatHandlerFunc func(SecretsServiceRunHeartBeatParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceRunHeartBeatHandlerFunc) Handle(params SecretsServiceRunHeartBeatParams, principal *jwt.MapClaims) middleware.Responder {
	return fn(params, principal)
}

// SecretsServiceRunHeartBeatHandler interface for that can handle valid secrets service run heart beat params
type SecretsServiceRunHeartBeatHandler interface {
	Handle(SecretsServiceRunHeartBeatParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceRunHeartBeat creates a new http.Handler for the secrets service run heart beat operation
func NewSecretsServiceRunHeartBeat(ctx *middleware.Context, handler SecretsServiceRunHeartBeatHandler) *SecretsServiceRunHeartBeat {
	return &SecretsServiceRunHeartBeat{Context: ctx, Handler: handler}
}

/*
	SecretsServiceRunHeartBeat swagger:route POST /api/v1/secrets/{id}/heartbeat Secrets secretsServiceRunHeartBeat

# Run Secret Heartbeat

Check if secret is still valid
*/
type SecretsServiceRunHeartBeat struct {
	Context *middleware.Context
	Handler SecretsServiceRunHeartBeatHandler
}

func (o *SecretsServiceRunHeartBeat) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewSecretsServiceRunHeartBeatParams()
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