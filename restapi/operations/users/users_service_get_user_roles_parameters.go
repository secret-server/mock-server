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

// NewUsersServiceGetUserRolesParams creates a new UsersServiceGetUserRolesParams object
//
// There are no default values defined in the spec.
func NewUsersServiceGetUserRolesParams() UsersServiceGetUserRolesParams {

	return UsersServiceGetUserRolesParams{}
}

// UsersServiceGetUserRolesParams contains all the bound params for the users service get user roles operation
// typically these are obtained from a http.Request
//
// swagger:parameters UsersService_GetUserRoles
type UsersServiceGetUserRolesParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Number of records to skip before taking results
	  In: query
	*/
	Skip *int32
	/*Sort direction
	  In: query
	*/
	SortBy0Direction *string
	/*Sort field name
	  In: query
	*/
	SortBy0Name *string
	/*Priority index. Sorts with lower values are executed earlier
	  In: query
	*/
	SortBy0Priority *int32
	/*Maximum number of records to include in results
	  In: query
	*/
	Take *int32
	/*User ID
	  Required: true
	  In: path
	*/
	UserID int32
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewUsersServiceGetUserRolesParams() beforehand.
func (o *UsersServiceGetUserRolesParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qSkip, qhkSkip, _ := qs.GetOK("skip")
	if err := o.bindSkip(qSkip, qhkSkip, route.Formats); err != nil {
		res = append(res, err)
	}

	qSortBy0Direction, qhkSortBy0Direction, _ := qs.GetOK("sortBy[0].direction")
	if err := o.bindSortBy0Direction(qSortBy0Direction, qhkSortBy0Direction, route.Formats); err != nil {
		res = append(res, err)
	}

	qSortBy0Name, qhkSortBy0Name, _ := qs.GetOK("sortBy[0].name")
	if err := o.bindSortBy0Name(qSortBy0Name, qhkSortBy0Name, route.Formats); err != nil {
		res = append(res, err)
	}

	qSortBy0Priority, qhkSortBy0Priority, _ := qs.GetOK("sortBy[0].priority")
	if err := o.bindSortBy0Priority(qSortBy0Priority, qhkSortBy0Priority, route.Formats); err != nil {
		res = append(res, err)
	}

	qTake, qhkTake, _ := qs.GetOK("take")
	if err := o.bindTake(qTake, qhkTake, route.Formats); err != nil {
		res = append(res, err)
	}

	rUserID, rhkUserID, _ := route.Params.GetOK("userId")
	if err := o.bindUserID(rUserID, rhkUserID, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindSkip binds and validates parameter Skip from query.
func (o *UsersServiceGetUserRolesParams) bindSkip(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt32(raw)
	if err != nil {
		return errors.InvalidType("skip", "query", "int32", raw)
	}
	o.Skip = &value

	return nil
}

// bindSortBy0Direction binds and validates parameter SortBy0Direction from query.
func (o *UsersServiceGetUserRolesParams) bindSortBy0Direction(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}
	o.SortBy0Direction = &raw

	return nil
}

// bindSortBy0Name binds and validates parameter SortBy0Name from query.
func (o *UsersServiceGetUserRolesParams) bindSortBy0Name(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}
	o.SortBy0Name = &raw

	return nil
}

// bindSortBy0Priority binds and validates parameter SortBy0Priority from query.
func (o *UsersServiceGetUserRolesParams) bindSortBy0Priority(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt32(raw)
	if err != nil {
		return errors.InvalidType("sortBy[0].priority", "query", "int32", raw)
	}
	o.SortBy0Priority = &value

	return nil
}

// bindTake binds and validates parameter Take from query.
func (o *UsersServiceGetUserRolesParams) bindTake(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt32(raw)
	if err != nil {
		return errors.InvalidType("take", "query", "int32", raw)
	}
	o.Take = &value

	return nil
}

// bindUserID binds and validates parameter UserID from path.
func (o *UsersServiceGetUserRolesParams) bindUserID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route

	value, err := swag.ConvertInt32(raw)
	if err != nil {
		return errors.InvalidType("userId", "path", "int32", raw)
	}
	o.UserID = value

	return nil
}