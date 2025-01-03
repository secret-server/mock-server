// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// RolesServicePatchGroupsOKCode is the HTTP code returned for type RolesServicePatchGroupsOK
const RolesServicePatchGroupsOKCode int = 200

/*
RolesServicePatchGroupsOK Role object

swagger:response rolesServicePatchGroupsOK
*/
type RolesServicePatchGroupsOK struct {

    /*
      In: Body
    */
    Payload *models.RoleGroupsPatchResult `json:"body,omitempty"`
}

// NewRolesServicePatchGroupsOK creates RolesServicePatchGroupsOK with default headers values
func NewRolesServicePatchGroupsOK() *RolesServicePatchGroupsOK {

    return &RolesServicePatchGroupsOK{}
}

// WithPayload adds the payload to the roles service patch groups o k response
func (o *RolesServicePatchGroupsOK) WithPayload(payload *models.RoleGroupsPatchResult) *RolesServicePatchGroupsOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service patch groups o k response
func (o *RolesServicePatchGroupsOK) SetPayload(payload *models.RoleGroupsPatchResult) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServicePatchGroupsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServicePatchGroupsBadRequestCode is the HTTP code returned for type RolesServicePatchGroupsBadRequest
const RolesServicePatchGroupsBadRequestCode int = 400

/*
RolesServicePatchGroupsBadRequest Bad request

swagger:response rolesServicePatchGroupsBadRequest
*/
type RolesServicePatchGroupsBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewRolesServicePatchGroupsBadRequest creates RolesServicePatchGroupsBadRequest with default headers values
func NewRolesServicePatchGroupsBadRequest() *RolesServicePatchGroupsBadRequest {

    return &RolesServicePatchGroupsBadRequest{}
}

// WithPayload adds the payload to the roles service patch groups bad request response
func (o *RolesServicePatchGroupsBadRequest) WithPayload(payload *models.BadRequestResponse) *RolesServicePatchGroupsBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service patch groups bad request response
func (o *RolesServicePatchGroupsBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServicePatchGroupsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServicePatchGroupsForbiddenCode is the HTTP code returned for type RolesServicePatchGroupsForbidden
const RolesServicePatchGroupsForbiddenCode int = 403

/*
RolesServicePatchGroupsForbidden Authentication failed

swagger:response rolesServicePatchGroupsForbidden
*/
type RolesServicePatchGroupsForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewRolesServicePatchGroupsForbidden creates RolesServicePatchGroupsForbidden with default headers values
func NewRolesServicePatchGroupsForbidden() *RolesServicePatchGroupsForbidden {

    return &RolesServicePatchGroupsForbidden{}
}

// WithPayload adds the payload to the roles service patch groups forbidden response
func (o *RolesServicePatchGroupsForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *RolesServicePatchGroupsForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service patch groups forbidden response
func (o *RolesServicePatchGroupsForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServicePatchGroupsForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServicePatchGroupsInternalServerErrorCode is the HTTP code returned for type RolesServicePatchGroupsInternalServerError
const RolesServicePatchGroupsInternalServerErrorCode int = 500

/*
RolesServicePatchGroupsInternalServerError Internal server error

swagger:response rolesServicePatchGroupsInternalServerError
*/
type RolesServicePatchGroupsInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewRolesServicePatchGroupsInternalServerError creates RolesServicePatchGroupsInternalServerError with default headers values
func NewRolesServicePatchGroupsInternalServerError() *RolesServicePatchGroupsInternalServerError {

    return &RolesServicePatchGroupsInternalServerError{}
}

// WithPayload adds the payload to the roles service patch groups internal server error response
func (o *RolesServicePatchGroupsInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *RolesServicePatchGroupsInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service patch groups internal server error response
func (o *RolesServicePatchGroupsInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServicePatchGroupsInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
