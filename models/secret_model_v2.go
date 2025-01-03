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

// SecretModelV2 Secret V2
//
// swagger:model SecretModelV2
type SecretModelV2 struct {

	// Access Request Workflow Map Id
	AccessRequestWorkflowMapID *int32 `json:"accessRequestWorkflowMapId,omitempty"`

	// Whether the secret is active
	Active bool `json:"active,omitempty"`

	// Allow Owners Unrestricted SSH Commands
	AllowOwnersUnrestrictedSSHCommands bool `json:"allowOwnersUnrestrictedSshCommands,omitempty"`

	// Auto Change Enabled
	AutoChangeEnabled bool `json:"autoChangeEnabled,omitempty"`

	// Auto Change Next Password
	AutoChangeNextPassword string `json:"autoChangeNextPassword,omitempty"`

	// Check Out Change Password Enabled
	CheckOutChangePasswordEnabled bool `json:"checkOutChangePasswordEnabled,omitempty"`

	// Whether secret checkout is enabled
	CheckOutEnabled bool `json:"checkOutEnabled,omitempty"`

	// Checkout interval, in minutes
	CheckOutIntervalMinutes int32 `json:"checkOutIntervalMinutes,omitempty"`

	// Minutes remaining in current checkout interval
	CheckOutMinutesRemaining int32 `json:"checkOutMinutesRemaining,omitempty"`

	// Name of user who has checked out the secret
	CheckOutUserDisplayName string `json:"checkOutUserDisplayName,omitempty"`

	// ID of user who has checked out the secret
	CheckOutUserID int32 `json:"checkOutUserId,omitempty"`

	// Whether the secret is currently checked out
	CheckedOut bool `json:"checkedOut,omitempty"`

	// DoubleLock Id
	DoubleLockID int32 `json:"doubleLockId,omitempty"`

	// Enable Inherit Permissions
	EnableInheritPermissions bool `json:"enableInheritPermissions,omitempty"`

	// Whether the secret policy is inherited from the containing folder
	EnableInheritSecretPolicy bool `json:"enableInheritSecretPolicy,omitempty"`

	// Number of failed password change attempts
	FailedPasswordChangeAttempts int32 `json:"failedPasswordChangeAttempts,omitempty"`

	// Containing folder ID
	FolderID int32 `json:"folderId,omitempty"`

	// Secret ID
	ID int32 `json:"id,omitempty"`

	// Whether double lock is enabled
	IsDoubleLock bool `json:"isDoubleLock,omitempty"`

	// Out of sync indicates that a Password is setup for autochange and has failed its last password change attempt or has exceeded the maximum RPC attempts
	IsOutOfSync bool `json:"isOutOfSync,omitempty"`

	// Whether the secret is restricted
	IsRestricted bool `json:"isRestricted,omitempty"`

	// Secret data fields
	Items []*RestSecretItem `json:"items"`

	// Jumpbox Route Id
	// Format: uuid
	JumpboxRouteID *strfmt.UUID `json:"jumpboxRouteId,omitempty"`

	// Time of last heartbeat check
	// Format: date-time
	LastHeartBeatCheck *strfmt.DateTime `json:"lastHeartBeatCheck,omitempty"`

	// Current status of heartbeat
	LastHeartBeatStatus HeartbeatStatus `json:"lastHeartBeatStatus,omitempty"`

	// Time of most recent password change attempt
	// Format: date-time
	LastPasswordChangeAttempt *strfmt.DateTime `json:"lastPasswordChangeAttempt,omitempty"`

	// LauncherConnectAsSecretId
	LauncherConnectAsSecretID *int32 `json:"launcherConnectAsSecretId,omitempty"`

	// Secret name
	Name string `json:"name,omitempty"`

	// Reason message if the secret is out of sync
	OutOfSyncReason string `json:"outOfSyncReason,omitempty"`

	// Password Type Web Script Id
	PasswordTypeWebScriptID int32 `json:"passwordTypeWebScriptId,omitempty"`

	// Proxy Enabled
	ProxyEnabled bool `json:"proxyEnabled,omitempty"`

	// Requires Approval For Access
	RequiresApprovalForAccess bool `json:"requiresApprovalForAccess,omitempty"`

	// Requires Comment
	RequiresComment bool `json:"requiresComment,omitempty"`

	// Response Codes
	ResponseCodes []string `json:"responseCodes"`

	// Restrict SSH Commands
	RestrictSSHCommands bool `json:"restrictSshCommands,omitempty"`

	// Secret Policy Id
	SecretPolicyID int32 `json:"secretPolicyId,omitempty"`

	// Secret template ID
	SecretTemplateID int32 `json:"secretTemplateId,omitempty"`

	// Name of secret template
	SecretTemplateName string `json:"secretTemplateName,omitempty"`

	// Whether session recording is enabled
	SessionRecordingEnabled bool `json:"sessionRecordingEnabled,omitempty"`

	// Site Id
	SiteID int32 `json:"siteId,omitempty"`

	// Web Launcher Requires Incognito Mode
	WebLauncherRequiresIncognitoMode bool `json:"webLauncherRequiresIncognitoMode,omitempty"`
}

// Validate validates this secret model v2
func (m *SecretModelV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateItems(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateJumpboxRouteID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastHeartBeatCheck(formats); err != nil {
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

func (m *SecretModelV2) validateItems(formats strfmt.Registry) error {
	if swag.IsZero(m.Items) { // not required
		return nil
	}

	for i := 0; i < len(m.Items); i++ {
		if swag.IsZero(m.Items[i]) { // not required
			continue
		}

		if m.Items[i] != nil {
			if err := m.Items[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("items" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SecretModelV2) validateJumpboxRouteID(formats strfmt.Registry) error {
	if swag.IsZero(m.JumpboxRouteID) { // not required
		return nil
	}

	if err := validate.FormatOf("jumpboxRouteId", "body", "uuid", m.JumpboxRouteID.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SecretModelV2) validateLastHeartBeatCheck(formats strfmt.Registry) error {
	if swag.IsZero(m.LastHeartBeatCheck) { // not required
		return nil
	}

	if err := validate.FormatOf("lastHeartBeatCheck", "body", "date-time", m.LastHeartBeatCheck.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *SecretModelV2) validateLastHeartBeatStatus(formats strfmt.Registry) error {
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

func (m *SecretModelV2) validateLastPasswordChangeAttempt(formats strfmt.Registry) error {
	if swag.IsZero(m.LastPasswordChangeAttempt) { // not required
		return nil
	}

	if err := validate.FormatOf("lastPasswordChangeAttempt", "body", "date-time", m.LastPasswordChangeAttempt.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this secret model v2 based on the context it is used
func (m *SecretModelV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateItems(ctx, formats); err != nil {
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

func (m *SecretModelV2) contextValidateItems(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Items); i++ {

		if m.Items[i] != nil {

			if swag.IsZero(m.Items[i]) { // not required
				return nil
			}

			if err := m.Items[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("items" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("items" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *SecretModelV2) contextValidateLastHeartBeatStatus(ctx context.Context, formats strfmt.Registry) error {

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
func (m *SecretModelV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SecretModelV2) UnmarshalBinary(b []byte) error {
	var res SecretModelV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
