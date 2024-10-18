// Code generated by go-swagger; DO NOT EDIT.

package secrets

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

// NewSecretsServiceGetLookupParams creates a new SecretsServiceGetLookupParams object
//
// There are no default values defined in the spec.
func NewSecretsServiceGetLookupParams() SecretsServiceGetLookupParams {

	return SecretsServiceGetLookupParams{}
}

// SecretsServiceGetLookupParams contains all the bound params for the secrets service get lookup operation
// typically these are obtained from a http.Request
//
// swagger:parameters SecretsService_GetLookup
type SecretsServiceGetLookupParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Secret ID
	  Required: true
	  In: path
	*/
	ID int32
	/*A full path including folder and secret name can be passed as a query string parameter when the secret ID is set to 0.  This will lookup the secret ID by path.
	  In: query
	*/
	SecretPath *string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewSecretsServiceGetLookupParams() beforehand.
func (o *SecretsServiceGetLookupParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	rID, rhkID, _ := route.Params.GetOK("id")
	if err := o.bindID(rID, rhkID, route.Formats); err != nil {
		res = append(res, err)
	}

	qSecretPath, qhkSecretPath, _ := qs.GetOK("secretPath")
	if err := o.bindSecretPath(qSecretPath, qhkSecretPath, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindID binds and validates parameter ID from path.
func (o *SecretsServiceGetLookupParams) bindID(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindSecretPath binds and validates parameter SecretPath from query.
func (o *SecretsServiceGetLookupParams) bindSecretPath(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}
	o.SecretPath = &raw

	return nil
}