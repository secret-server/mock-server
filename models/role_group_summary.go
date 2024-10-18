// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// RoleGroupSummary Group
//
// swagger:model RoleGroupSummary
type RoleGroupSummary struct {

	// Created Date
	// Format: date-time
	Created strfmt.DateTime `json:"created,omitempty"`

	// Group display name
	DisplayName string `json:"displayName,omitempty"`

	// Active Directory domain name
	DomainName string `json:"domainName,omitempty"`

	// Whether the group is active
	Enabled bool `json:"enabled,omitempty"`

	// Group ID
	GroupID int32 `json:"groupId,omitempty"`

	// Group name
	Name string `json:"name,omitempty"`

	// Whether the group is for a single user
	Personal bool `json:"personal,omitempty"`
}

// Validate validates this role group summary
func (m *RoleGroupSummary) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreated(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *RoleGroupSummary) validateCreated(formats strfmt.Registry) error {
	if swag.IsZero(m.Created) { // not required
		return nil
	}

	if err := validate.FormatOf("created", "body", "date-time", m.Created.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this role group summary based on context it is used
func (m *RoleGroupSummary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RoleGroupSummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RoleGroupSummary) UnmarshalBinary(b []byte) error {
	var res RoleGroupSummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
