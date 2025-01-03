// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// SecretsServiceGetSecretExtendedSearchDetailsHandlerFunc turns a function with the right signature into a secrets service get secret extended search details handler
type SecretsServiceGetSecretExtendedSearchDetailsHandlerFunc func(SecretsServiceGetSecretExtendedSearchDetailsParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceGetSecretExtendedSearchDetailsHandlerFunc) Handle(params SecretsServiceGetSecretExtendedSearchDetailsParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// SecretsServiceGetSecretExtendedSearchDetailsHandler interface for that can handle valid secrets service get secret extended search details params
type SecretsServiceGetSecretExtendedSearchDetailsHandler interface {
    Handle(SecretsServiceGetSecretExtendedSearchDetailsParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceGetSecretExtendedSearchDetails creates a new http.Handler for the secrets service get secret extended search details operation
func NewSecretsServiceGetSecretExtendedSearchDetails(ctx *middleware.Context, handler SecretsServiceGetSecretExtendedSearchDetailsHandler) *SecretsServiceGetSecretExtendedSearchDetails {
    return &SecretsServiceGetSecretExtendedSearchDetails{Context: ctx, Handler: handler}
}

/*
    SecretsServiceGetSecretExtendedSearchDetails swagger:route POST /api/v1/secrets/extended-search-details Secrets secretsServiceGetSecretExtendedSearchDetails

# Secret Search Extended Details

Pass an array of secret IDs, presumably the results of a secret search and get extended details such as has launchers or is favorite.
*/
type SecretsServiceGetSecretExtendedSearchDetails struct {
    Context *middleware.Context
    Handler SecretsServiceGetSecretExtendedSearchDetailsHandler
}

func (o *SecretsServiceGetSecretExtendedSearchDetails) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewSecretsServiceGetSecretExtendedSearchDetailsParams()
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
