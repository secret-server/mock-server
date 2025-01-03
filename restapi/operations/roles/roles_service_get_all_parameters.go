// Code generated by go-swagger; DO NOT EDIT.

package roles

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

// NewRolesServiceGetAllParams creates a new RolesServiceGetAllParams object
//
// There are no default values defined in the spec.
func NewRolesServiceGetAllParams() RolesServiceGetAllParams {

    return RolesServiceGetAllParams{}
}

// RolesServiceGetAllParams contains all the bound params for the roles service get all operation
// typically these are obtained from a http.Request
//
// swagger:parameters RolesService_GetAll
type RolesServiceGetAllParams struct {

    // HTTP Request Object
    HTTPRequest *http.Request `json:"-"`

    /*Only return roles assigned to this group id.  Will be ignored if UserId is set
      In: query
    */
    FilterGroupID *int32
    /*Whether to include inactive Roles in the results
      In: query
    */
    FilterIncludeInactive *bool
    /*Only return roles assigned to this user id.  Will supercede GroupId if set
      In: query
    */
    FilterUserID *int32
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
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewRolesServiceGetAllParams() beforehand.
func (o *RolesServiceGetAllParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
    var res []error

    o.HTTPRequest = r

    qs := runtime.Values(r.URL.Query())

    qFilterGroupID, qhkFilterGroupID, _ := qs.GetOK("filter.groupId")
    if err := o.bindFilterGroupID(qFilterGroupID, qhkFilterGroupID, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterIncludeInactive, qhkFilterIncludeInactive, _ := qs.GetOK("filter.includeInactive")
    if err := o.bindFilterIncludeInactive(qFilterIncludeInactive, qhkFilterIncludeInactive, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterUserID, qhkFilterUserID, _ := qs.GetOK("filter.userId")
    if err := o.bindFilterUserID(qFilterUserID, qhkFilterUserID, route.Formats); err != nil {
        res = append(res, err)
    }

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
    if len(res) > 0 {
        return errors.CompositeValidationError(res...)
    }
    return nil
}

// bindFilterGroupID binds and validates parameter FilterGroupID from query.
func (o *RolesServiceGetAllParams) bindFilterGroupID(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
        return errors.InvalidType("filter.groupId", "query", "int32", raw)
    }
    o.FilterGroupID = &value

    return nil
}

// bindFilterIncludeInactive binds and validates parameter FilterIncludeInactive from query.
func (o *RolesServiceGetAllParams) bindFilterIncludeInactive(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("filter.includeInactive", "query", "bool", raw)
	}
	o.FilterIncludeInactive = &value

	return nil
}

// bindFilterUserID binds and validates parameter FilterUserID from query.
func (o *RolesServiceGetAllParams) bindFilterUserID(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("filter.userId", "query", "int32", raw)
	}
	o.FilterUserID = &value

	return nil
}

// bindSkip binds and validates parameter Skip from query.
func (o *RolesServiceGetAllParams) bindSkip(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *RolesServiceGetAllParams) bindSortBy0Direction(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *RolesServiceGetAllParams) bindSortBy0Name(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *RolesServiceGetAllParams) bindSortBy0Priority(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *RolesServiceGetAllParams) bindTake(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
