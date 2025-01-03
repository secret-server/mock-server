// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RoleGroupsPatchModel Data
//
// swagger:model RoleGroupsPatchModel
type RoleGroupsPatchModel struct {

	// IDs of Groups to add to Role
	GroupIdsToAdd *UpdateFieldValueOfInt32 `json:"groupIdsToAdd,omitempty"`

	// IDs of Groups to remove from Role
	GroupIdsToRemove *UpdateFieldValueOfInt32 `json:"groupIdsToRemove,omitempty"`
}

// Validate validates this role groups patch model
func (m *RoleGroupsPatchModel) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateGroupIdsToAdd(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGroupIdsToRemove(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RoleGroupsPatchModel) validateGroupIdsToAdd(formats strfmt.Registry) error {
	if swag.IsZero(m.GroupIdsToAdd) { // not required
		return nil
	}

	if m.GroupIdsToAdd != nil {
		if err := m.GroupIdsToAdd.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("groupIdsToAdd")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("groupIdsToAdd")
			}
			return err
		}
	}

	return nil
}

func (m *RoleGroupsPatchModel) validateGroupIdsToRemove(formats strfmt.Registry) error {
	if swag.IsZero(m.GroupIdsToRemove) { // not required
		return nil
	}

	if m.GroupIdsToRemove != nil {
		if err := m.GroupIdsToRemove.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("groupIdsToRemove")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("groupIdsToRemove")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this role groups patch model based on the context it is used
func (m *RoleGroupsPatchModel) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGroupIdsToAdd(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateGroupIdsToRemove(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RoleGroupsPatchModel) contextValidateGroupIdsToAdd(ctx context.Context, formats strfmt.Registry) error {

	if m.GroupIdsToAdd != nil {

		if swag.IsZero(m.GroupIdsToAdd) { // not required
			return nil
		}

		if err := m.GroupIdsToAdd.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("groupIdsToAdd")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("groupIdsToAdd")
			}
			return err
		}
	}

	return nil
}

func (m *RoleGroupsPatchModel) contextValidateGroupIdsToRemove(ctx context.Context, formats strfmt.Registry) error {

	if m.GroupIdsToRemove != nil {

		if swag.IsZero(m.GroupIdsToRemove) { // not required
			return nil
		}

		if err := m.GroupIdsToRemove.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("groupIdsToRemove")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("groupIdsToRemove")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *RoleGroupsPatchModel) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RoleGroupsPatchModel) UnmarshalBinary(b []byte) error {
	var res RoleGroupsPatchModel
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
