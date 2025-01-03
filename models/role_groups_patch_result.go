// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RoleGroupsPatchResult RoleGroupsPatchResult
//
// swagger:model RoleGroupsPatchResult
type RoleGroupsPatchResult struct {

	// Success
	Success bool `json:"success,omitempty"`
}

// Validate validates this role groups patch result
func (m *RoleGroupsPatchResult) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this role groups patch result based on context it is used
func (m *RoleGroupsPatchResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RoleGroupsPatchResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RoleGroupsPatchResult) UnmarshalBinary(b []byte) error {
	var res RoleGroupsPatchResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
