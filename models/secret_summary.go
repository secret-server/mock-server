// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// SecretSummary Secret summary
//
// swagger:model SecretSummary
type SecretSummary struct {

	// Whether the secret is active
	Active bool `json:"active,omitempty"`

	// Indicates whether or not this Secret an auto changing password
	AutoChangeEnabled *bool `json:"autoChangeEnabled,omitempty"`

	// Indicates whether or not checkout is enabled for the Secret
	CheckOutEnabled *bool `json:"checkOutEnabled,omitempty"`

	// Id of the User that has the secret checked out if it is checked out
	CheckOutUserID int32 `json:"checkOutUserId,omitempty"`

	// The name of the User that has the secret checked out if it is checked out
	CheckOutUserName string `json:"checkOutUserName,omitempty"`

	// Whether the secret is currently checked out
	CheckedOut bool `json:"checkedOut,omitempty"`

	// When the Secret was created
	// Format: date-time
	CreateDate *strfmt.DateTime `json:"createDate,omitempty"`

	// How many days until this Secret expires
	DaysUntilExpiration *int32 `json:"daysUntilExpiration,omitempty"`

	// Indicates whether or not DoubleLock is enabled for this password
	DoubleLockEnabled *bool `json:"doubleLockEnabled,omitempty"`

	// Any requested extended fields from a lookup request
	ExtendedFields []*ISecretSummaryExtendedField `json:"extendedFields"`

	// Containing folder ID
	FolderID int32 `json:"folderId,omitempty"`

	// Containing folder path
	FolderPath string `json:"folderPath,omitempty"`

	// Indicates if this Secret has any launchers
	HasLauncher bool `json:"hasLauncher,omitempty"`

	// Indicates if the launcher password is set to be hidden
	HidePassword *bool `json:"hidePassword,omitempty"`

	// Secret ID
	ID int32 `json:"id,omitempty"`

	// Indicates if this Secret inherits permissions from its folder
	InheritsPermissions *bool `json:"inheritsPermissions,omitempty"`

	// Indicates that Heartbeat has failed or a Password is set up for autochange and has failed its last password change attempt or has exceeded the maximum RPC attempts
	IsOutOfSync bool `json:"isOutOfSync,omitempty"`

	// Whether the secret is restricted
	IsRestricted bool `json:"isRestricted,omitempty"`

	// When the Secret was last viewed by the current User
	// Format: date-time
	LastAccessed *strfmt.DateTime `json:"lastAccessed,omitempty"`

	// Current status of heartbeat
	LastHeartBeatStatus HeartbeatStatus `json:"lastHeartBeatStatus,omitempty"`

	// Time of most recent password change attempt
	// Format: date-time
	LastPasswordChangeAttempt *strfmt.DateTime `json:"lastPasswordChangeAttempt,omitempty"`

	// Secret name
	Name string `json:"name,omitempty"`

	// Reason message if the secret is out of sync
	OutOfSyncReason string `json:"outOfSyncReason,omitempty"`

	// Indicates if this Secret requires approval
	RequiresApproval *bool `json:"requiresApproval,omitempty"`

	// Indicates if this Secret requires comment
	RequiresComment *bool `json:"requiresComment,omitempty"`

	// ResponseCodes
	ResponseCodes []string `json:"responseCodes"`

	// Secret template ID
	SecretTemplateID int32 `json:"secretTemplateId,omitempty"`

	// Name of secret template
	SecretTemplateName string `json:"secretTemplateName,omitempty"`

	// SiteId
	SiteID int32 `json:"siteId,omitempty"`
}

// Validate validates this secret summary
func (m *SecretSummary) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreateDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExtendedFields(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastAccessed(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastHeartBeatStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastPasswordChangeAttempt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SecretSummary) validateCreateDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CreateDate) { // not required
		return nil
	}

	if err := validate.FormatOf("createDate", "body", "date-time", m.CreateDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SecretSummary) validateExtendedFields(formats strfmt.Registry) error {
	if swag.IsZero(m.ExtendedFields) { // not required
		return nil
	}

	for i := 0; i < len(m.ExtendedFields); i++ {
		if swag.IsZero(m.ExtendedFields[i]) { // not required
			continue
		}

		if m.ExtendedFields[i] != nil {
			if err := m.ExtendedFields[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("extendedFields" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("extendedFields" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SecretSummary) validateLastAccessed(formats strfmt.Registry) error {
	if swag.IsZero(m.LastAccessed) { // not required
		return nil
	}

	if err := validate.FormatOf("lastAccessed", "body", "date-time", m.LastAccessed.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SecretSummary) validateLastHeartBeatStatus(formats strfmt.Registry) error {
	if swag.IsZero(m.LastHeartBeatStatus) { // not required
		return nil
	}

	if err := m.LastHeartBeatStatus.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("lastHeartBeatStatus")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("lastHeartBeatStatus")
		}
		return err
	}

	return nil
}

func (m *SecretSummary) validateLastPasswordChangeAttempt(formats strfmt.Registry) error {
	if swag.IsZero(m.LastPasswordChangeAttempt) { // not required
		return nil
	}

	if err := validate.FormatOf("lastPasswordChangeAttempt", "body", "date-time", m.LastPasswordChangeAttempt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this secret summary based on the context it is used
func (m *SecretSummary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateExtendedFields(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateLastHeartBeatStatus(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SecretSummary) contextValidateExtendedFields(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ExtendedFields); i++ {

		if m.ExtendedFields[i] != nil {

			if swag.IsZero(m.ExtendedFields[i]) { // not required
				return nil
			}

			if err := m.ExtendedFields[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("extendedFields" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("extendedFields" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SecretSummary) contextValidateLastHeartBeatStatus(ctx context.Context, formats strfmt.Registry) error {

	if swag.IsZero(m.LastHeartBeatStatus) { // not required
		return nil
	}

	if err := m.LastHeartBeatStatus.ContextValidate(ctx, formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("lastHeartBeatStatus")
		} else if ce, ok := err.(*errors.CompositeError); ok {
			return ce.ValidateName("lastHeartBeatStatus")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SecretSummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SecretSummary) UnmarshalBinary(b []byte) error {
	var res SecretSummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
