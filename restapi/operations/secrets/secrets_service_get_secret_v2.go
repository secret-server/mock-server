// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// SecretsServiceGetSecretV2HandlerFunc turns a function with the right signature into a secrets service get secret v2 handler
type SecretsServiceGetSecretV2HandlerFunc func(SecretsServiceGetSecretV2Params, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceGetSecretV2HandlerFunc) Handle(params SecretsServiceGetSecretV2Params, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// SecretsServiceGetSecretV2Handler interface for that can handle valid secrets service get secret v2 params
type SecretsServiceGetSecretV2Handler interface {
    Handle(SecretsServiceGetSecretV2Params, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceGetSecretV2 creates a new http.Handler for the secrets service get secret v2 operation
func NewSecretsServiceGetSecretV2(ctx *middleware.Context, handler SecretsServiceGetSecretV2Handler) *SecretsServiceGetSecretV2 {
    return &SecretsServiceGetSecretV2{Context: ctx, Handler: handler}
}

/*
    SecretsServiceGetSecretV2 swagger:route GET /api/v2/secrets/{id} Secrets secretsServiceGetSecretV2

# Get Secret

Get a single secret by ID
*/
type SecretsServiceGetSecretV2 struct {
    Context *middleware.Context
    Handler SecretsServiceGetSecretV2Handler
}

func (o *SecretsServiceGetSecretV2) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewSecretsServiceGetSecretV2Params()
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
