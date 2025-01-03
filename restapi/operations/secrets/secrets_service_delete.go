// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "net/http"

    "github.com/go-openapi/runtime/middleware"

    "github.com/golang-jwt/jwt"
)

// SecretsServiceDeleteHandlerFunc turns a function with the right signature into a secrets service delete handler
type SecretsServiceDeleteHandlerFunc func(SecretsServiceDeleteParams, *jwt.MapClaims) middleware.Responder

// Handle executing the request and returning a response
func (fn SecretsServiceDeleteHandlerFunc) Handle(params SecretsServiceDeleteParams, principal *jwt.MapClaims) middleware.Responder {
    return fn(params, principal)
}

// SecretsServiceDeleteHandler interface for that can handle valid secrets service delete params
type SecretsServiceDeleteHandler interface {
    Handle(SecretsServiceDeleteParams, *jwt.MapClaims) middleware.Responder
}

// NewSecretsServiceDelete creates a new http.Handler for the secrets service delete operation
func NewSecretsServiceDelete(ctx *middleware.Context, handler SecretsServiceDeleteHandler) *SecretsServiceDelete {
    return &SecretsServiceDelete{Context: ctx, Handler: handler}
}

/*
    SecretsServiceDelete swagger:route DELETE /api/v1/secrets/{id} Secrets secretsServiceDelete

# Deactivate a Secret

A deactivated secret is hidden from users who do not have a role containing the View Inactive Secrets permission. Secret Server uses these "soft deletes" to maintain the audit history for all data. However, deactivated secrets are still accessible by administrators (like a permanent Recycle Bin) to ensure that audit history is maintained and to support recovery. A user must have the "View Inactive Secrets" permission in addition to Owner permission on a secret to access the secret View page for a deleted secret. To permanently remove all information on a secret, use the "Erase Secret" function.
*/
type SecretsServiceDelete struct {
    Context *middleware.Context
    Handler SecretsServiceDeleteHandler
}

func (o *SecretsServiceDelete) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
    route, rCtx, _ := o.Context.RouteInfo(r)
    if rCtx != nil {
        *r = *rCtx
    }
    var Params = NewSecretsServiceDeleteParams()
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
