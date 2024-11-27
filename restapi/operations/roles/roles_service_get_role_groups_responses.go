// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// RolesServiceGetRoleGroupsOKCode is the HTTP code returned for type RolesServiceGetRoleGroupsOK
const RolesServiceGetRoleGroupsOKCode int = 200

/*
RolesServiceGetRoleGroupsOK Role Group summary result object

swagger:response rolesServiceGetRoleGroupsOK
*/
type RolesServiceGetRoleGroupsOK struct {

    /*
      In: Body
    */
    Payload *models.PagingOfRoleGroupSummaryAndGroupMembershipFilter `json:"body,omitempty"`
}

// NewRolesServiceGetRoleGroupsOK creates RolesServiceGetRoleGroupsOK with default headers values
func NewRolesServiceGetRoleGroupsOK() *RolesServiceGetRoleGroupsOK {

    return &RolesServiceGetRoleGroupsOK{}
}

// WithPayload adds the payload to the roles service get role groups o k response
func (o *RolesServiceGetRoleGroupsOK) WithPayload(payload *models.PagingOfRoleGroupSummaryAndGroupMembershipFilter) *RolesServiceGetRoleGroupsOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get role groups o k response
func (o *RolesServiceGetRoleGroupsOK) SetPayload(payload *models.PagingOfRoleGroupSummaryAndGroupMembershipFilter) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetRoleGroupsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceGetRoleGroupsBadRequestCode is the HTTP code returned for type RolesServiceGetRoleGroupsBadRequest
const RolesServiceGetRoleGroupsBadRequestCode int = 400

/*
RolesServiceGetRoleGroupsBadRequest Bad request

swagger:response rolesServiceGetRoleGroupsBadRequest
*/
type RolesServiceGetRoleGroupsBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewRolesServiceGetRoleGroupsBadRequest creates RolesServiceGetRoleGroupsBadRequest with default headers values
func NewRolesServiceGetRoleGroupsBadRequest() *RolesServiceGetRoleGroupsBadRequest {

    return &RolesServiceGetRoleGroupsBadRequest{}
}

// WithPayload adds the payload to the roles service get role groups bad request response
func (o *RolesServiceGetRoleGroupsBadRequest) WithPayload(payload *models.BadRequestResponse) *RolesServiceGetRoleGroupsBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get role groups bad request response
func (o *RolesServiceGetRoleGroupsBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetRoleGroupsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceGetRoleGroupsForbiddenCode is the HTTP code returned for type RolesServiceGetRoleGroupsForbidden
const RolesServiceGetRoleGroupsForbiddenCode int = 403

/*
RolesServiceGetRoleGroupsForbidden Authentication failed

swagger:response rolesServiceGetRoleGroupsForbidden
*/
type RolesServiceGetRoleGroupsForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewRolesServiceGetRoleGroupsForbidden creates RolesServiceGetRoleGroupsForbidden with default headers values
func NewRolesServiceGetRoleGroupsForbidden() *RolesServiceGetRoleGroupsForbidden {

    return &RolesServiceGetRoleGroupsForbidden{}
}

// WithPayload adds the payload to the roles service get role groups forbidden response
func (o *RolesServiceGetRoleGroupsForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *RolesServiceGetRoleGroupsForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get role groups forbidden response
func (o *RolesServiceGetRoleGroupsForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetRoleGroupsForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceGetRoleGroupsInternalServerErrorCode is the HTTP code returned for type RolesServiceGetRoleGroupsInternalServerError
const RolesServiceGetRoleGroupsInternalServerErrorCode int = 500

/*
RolesServiceGetRoleGroupsInternalServerError Internal server error

swagger:response rolesServiceGetRoleGroupsInternalServerError
*/
type RolesServiceGetRoleGroupsInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewRolesServiceGetRoleGroupsInternalServerError creates RolesServiceGetRoleGroupsInternalServerError with default headers values
func NewRolesServiceGetRoleGroupsInternalServerError() *RolesServiceGetRoleGroupsInternalServerError {

    return &RolesServiceGetRoleGroupsInternalServerError{}
}

// WithPayload adds the payload to the roles service get role groups internal server error response
func (o *RolesServiceGetRoleGroupsInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *RolesServiceGetRoleGroupsInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get role groups internal server error response
func (o *RolesServiceGetRoleGroupsInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetRoleGroupsInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
