// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// SecretsServiceSearchV2HandlerFunc turns a function with the right signature into a secrets service search v2 handler
type SecretsServiceSearchV2HandlerFunc func(SecretsServiceSearchV2Params, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceSearchV2HandlerFunc) Handle(params SecretsServiceSearchV2Params, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// SecretsServiceSearchV2Handler interface for that can handle valid secrets service search v2 params
type SecretsServiceSearchV2Handler interface {
    Handle(SecretsServiceSearchV2Params, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceSearchV2 creates a new http.Handler for the secrets service search v2 operation
func NewSecretsServiceSearchV2(ctx *middleware.Context, handler SecretsServiceSearchV2Handler) *SecretsServiceSearchV2 {
    return &SecretsServiceSearchV2{Context: ctx, Handler: handler}
}

/*
    SecretsServiceSearchV2 swagger:route GET /api/v2/secrets Secrets secretsServiceSearchV2

# Search Secrets

Search, filter, sort, and page secrets
*/
type SecretsServiceSearchV2 struct {
    Context *middleware.Context
    Handler SecretsServiceSearchV2Handler
}

func (o *SecretsServiceSearchV2) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewSecretsServiceSearchV2Params()
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
