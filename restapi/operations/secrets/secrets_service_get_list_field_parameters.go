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

// NewSecretsServiceGetListFieldParams creates a new SecretsServiceGetListFieldParams object
//
// There are no default values defined in the spec.
func NewSecretsServiceGetListFieldParams() SecretsServiceGetListFieldParams {

	return SecretsServiceGetListFieldParams{}
}

// SecretsServiceGetListFieldParams contains all the bound params for the secrets service get list field operation
// typically these are obtained from a http.Request
//
// swagger:parameters SecretsService_GetListField
type SecretsServiceGetListFieldParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Automatically check in a secret after finding or updating.
	  In: query
	*/
	AutoCheckIn *bool
	/*Automatically check out secret before finding or updating.
	  In: query
	*/
	AutoCheckout *bool
	/*Leave a comment when checking in or out.
	  In: query
	*/
	AutoComment *string
	/*If secret is checked out, then force a check in.
	  In: query
	*/
	ForceCheckIn *bool
	/*Secret ID
	  Required: true
	  In: path
	*/
	ID int32
	/*Secret field name
	  Required: true
	  In: path
	*/
	Slug string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewSecretsServiceGetListFieldParams() beforehand.
func (o *SecretsServiceGetListFieldParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qAutoCheckIn, qhkAutoCheckIn, _ := qs.GetOK("autoCheckIn")
	if err := o.bindAutoCheckIn(qAutoCheckIn, qhkAutoCheckIn, route.Formats); err != nil {
		res = append(res, err)
	}

	qAutoCheckout, qhkAutoCheckout, _ := qs.GetOK("autoCheckout")
	if err := o.bindAutoCheckout(qAutoCheckout, qhkAutoCheckout, route.Formats); err != nil {
		res = append(res, err)
	}

	qAutoComment, qhkAutoComment, _ := qs.GetOK("autoComment")
	if err := o.bindAutoComment(qAutoComment, qhkAutoComment, route.Formats); err != nil {
		res = append(res, err)
	}

	qForceCheckIn, qhkForceCheckIn, _ := qs.GetOK("forceCheckIn")
	if err := o.bindForceCheckIn(qForceCheckIn, qhkForceCheckIn, route.Formats); err != nil {
		res = append(res, err)
	}

	rID, rhkID, _ := route.Params.GetOK("id")
	if err := o.bindID(rID, rhkID, route.Formats); err != nil {
		res = append(res, err)
	}

	rSlug, rhkSlug, _ := route.Params.GetOK("slug")
	if err := o.bindSlug(rSlug, rhkSlug, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindAutoCheckIn binds and validates parameter AutoCheckIn from query.
func (o *SecretsServiceGetListFieldParams) bindAutoCheckIn(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("autoCheckIn", "query", "bool", raw)
	}
	o.AutoCheckIn = &value

	return nil
}

// bindAutoCheckout binds and validates parameter AutoCheckout from query.
func (o *SecretsServiceGetListFieldParams) bindAutoCheckout(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("autoCheckout", "query", "bool", raw)
	}
	o.AutoCheckout = &value

	return nil
}

// bindAutoComment binds and validates parameter AutoComment from query.
func (o *SecretsServiceGetListFieldParams) bindAutoComment(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}
	o.AutoComment = &raw

	return nil
}

// bindForceCheckIn binds and validates parameter ForceCheckIn from query.
func (o *SecretsServiceGetListFieldParams) bindForceCheckIn(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("forceCheckIn", "query", "bool", raw)
	}
	o.ForceCheckIn = &value

	return nil
}

// bindID binds and validates parameter ID from path.
func (o *SecretsServiceGetListFieldParams) bindID(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindSlug binds and validates parameter Slug from path.
func (o *SecretsServiceGetListFieldParams) bindSlug(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.Slug = raw

	return nil
}