// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// RolesServiceStubOKCode is the HTTP code returned for type RolesServiceStubOK
const RolesServiceStubOKCode int = 200

/*
RolesServiceStubOK Role object

swagger:response rolesServiceStubOK
*/
type RolesServiceStubOK struct {

    /*
      In: Body
    */
    Payload *models.RoleModel `json:"body,omitempty"`
}

// NewRolesServiceStubOK creates RolesServiceStubOK with default headers values
func NewRolesServiceStubOK() *RolesServiceStubOK {

    return &RolesServiceStubOK{}
}

// WithPayload adds the payload to the roles service stub o k response
func (o *RolesServiceStubOK) WithPayload(payload *models.RoleModel) *RolesServiceStubOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service stub o k response
func (o *RolesServiceStubOK) SetPayload(payload *models.RoleModel) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceStubOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceStubBadRequestCode is the HTTP code returned for type RolesServiceStubBadRequest
const RolesServiceStubBadRequestCode int = 400

/*
RolesServiceStubBadRequest Bad request

swagger:response rolesServiceStubBadRequest
*/
type RolesServiceStubBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewRolesServiceStubBadRequest creates RolesServiceStubBadRequest with default headers values
func NewRolesServiceStubBadRequest() *RolesServiceStubBadRequest {

    return &RolesServiceStubBadRequest{}
}

// WithPayload adds the payload to the roles service stub bad request response
func (o *RolesServiceStubBadRequest) WithPayload(payload *models.BadRequestResponse) *RolesServiceStubBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service stub bad request response
func (o *RolesServiceStubBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceStubBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceStubForbiddenCode is the HTTP code returned for type RolesServiceStubForbidden
const RolesServiceStubForbiddenCode int = 403

/*
RolesServiceStubForbidden Authentication failed

swagger:response rolesServiceStubForbidden
*/
type RolesServiceStubForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewRolesServiceStubForbidden creates RolesServiceStubForbidden with default headers values
func NewRolesServiceStubForbidden() *RolesServiceStubForbidden {

    return &RolesServiceStubForbidden{}
}

// WithPayload adds the payload to the roles service stub forbidden response
func (o *RolesServiceStubForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *RolesServiceStubForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service stub forbidden response
func (o *RolesServiceStubForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceStubForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceStubInternalServerErrorCode is the HTTP code returned for type RolesServiceStubInternalServerError
const RolesServiceStubInternalServerErrorCode int = 500

/*
RolesServiceStubInternalServerError Internal server error

swagger:response rolesServiceStubInternalServerError
*/
type RolesServiceStubInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewRolesServiceStubInternalServerError creates RolesServiceStubInternalServerError with default headers values
func NewRolesServiceStubInternalServerError() *RolesServiceStubInternalServerError {

    return &RolesServiceStubInternalServerError{}
}

// WithPayload adds the payload to the roles service stub internal server error response
func (o *RolesServiceStubInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *RolesServiceStubInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service stub internal server error response
func (o *RolesServiceStubInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceStubInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
