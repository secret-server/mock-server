// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// UpdateFieldValueOfOptionalInt32 The minimum length required for local user passwords
//
// swagger:model UpdateFieldValueOfOptionalInt32
type UpdateFieldValueOfOptionalInt32 struct {

	// Dirty
	Dirty bool `json:"dirty,omitempty"`

	// Value
	Value *int32 `json:"value,omitempty"`
}

// Validate validates this update field value of optional int32
func (m *UpdateFieldValueOfOptionalInt32) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this update field value of optional int32 based on context it is used
func (m *UpdateFieldValueOfOptionalInt32) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateFieldValueOfOptionalInt32) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateFieldValueOfOptionalInt32) UnmarshalBinary(b []byte) error {
	var res UpdateFieldValueOfOptionalInt32
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
