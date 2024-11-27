// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/errors"
    "github.com/go-openapi/runtime"
    "github.com/go-openapi/runtime/middleware"
    "github.com/go-openapi/strfmt"
    "github.com/go-openapi/swag"
)

// NewUsersServiceGetParams creates a new UsersServiceGetParams object
//
// There are no default values defined in the spec.
func NewUsersServiceGetParams() UsersServiceGetParams {

    return UsersServiceGetParams{}
}

// UsersServiceGetParams contains all the bound params for the users service get operation
// typically these are obtained from a http.Request
//
// swagger:parameters UsersService_Get
type UsersServiceGetParams struct {

    // HTTP Request Object
    HTTPRequest *http.Request `json:"-"`

    /*User ID
      Required: true
      In: path
    */
    ID int32
    /*Whether to include inactive users in the results
      In: query
    */
    IncludeInactive *bool
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewUsersServiceGetParams() beforehand.
func (o *UsersServiceGetParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
    var res []error

    o.HTTPRequest = r

    qs := runtime.Values(r.URL.Query())

    rID, rhkID, _ := route.Params.GetOK("id")
    if err := o.bindID(rID, rhkID, route.Formats); err != nil {
        res = append(res, err)
    }

    qIncludeInactive, qhkIncludeInactive, _ := qs.GetOK("includeInactive")
    if err := o.bindIncludeInactive(qIncludeInactive, qhkIncludeInactive, route.Formats); err != nil {
        res = append(res, err)
    }
    if len(res) > 0 {
        return errors.CompositeValidationError(res...)
    }
    return nil
}

// bindID binds and validates parameter ID from path.
func (o *UsersServiceGetParams) bindID(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: true
    // Parameter is provided by construction from the route

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("id", "path", "int32", raw)
    }
    o.ID = value

    return nil
}

// bindIncludeInactive binds and validates parameter IncludeInactive from query.
func (o *UsersServiceGetParams) bindIncludeInactive(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("includeInactive", "query", "bool", raw)
    }
    o.IncludeInactive = &value

    return nil
}
