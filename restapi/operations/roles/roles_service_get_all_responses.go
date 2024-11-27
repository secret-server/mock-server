// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// RolesServiceGetAllOKCode is the HTTP code returned for type RolesServiceGetAllOK
const RolesServiceGetAllOKCode int = 200

/*
RolesServiceGetAllOK Role search result object

swagger:response rolesServiceGetAllOK
*/
type RolesServiceGetAllOK struct {

    /*
      In: Body
    */
    Payload *models.PagingOfRoleModel `json:"body,omitempty"`
}

// NewRolesServiceGetAllOK creates RolesServiceGetAllOK with default headers values
func NewRolesServiceGetAllOK() *RolesServiceGetAllOK {

    return &RolesServiceGetAllOK{}
}

// WithPayload adds the payload to the roles service get all o k response
func (o *RolesServiceGetAllOK) WithPayload(payload *models.PagingOfRoleModel) *RolesServiceGetAllOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get all o k response
func (o *RolesServiceGetAllOK) SetPayload(payload *models.PagingOfRoleModel) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetAllOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceGetAllBadRequestCode is the HTTP code returned for type RolesServiceGetAllBadRequest
const RolesServiceGetAllBadRequestCode int = 400

/*
RolesServiceGetAllBadRequest Bad request

swagger:response rolesServiceGetAllBadRequest
*/
type RolesServiceGetAllBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewRolesServiceGetAllBadRequest creates RolesServiceGetAllBadRequest with default headers values
func NewRolesServiceGetAllBadRequest() *RolesServiceGetAllBadRequest {

    return &RolesServiceGetAllBadRequest{}
}

// WithPayload adds the payload to the roles service get all bad request response
func (o *RolesServiceGetAllBadRequest) WithPayload(payload *models.BadRequestResponse) *RolesServiceGetAllBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get all bad request response
func (o *RolesServiceGetAllBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetAllBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceGetAllForbiddenCode is the HTTP code returned for type RolesServiceGetAllForbidden
const RolesServiceGetAllForbiddenCode int = 403

/*
RolesServiceGetAllForbidden Authentication failed

swagger:response rolesServiceGetAllForbidden
*/
type RolesServiceGetAllForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewRolesServiceGetAllForbidden creates RolesServiceGetAllForbidden with default headers values
func NewRolesServiceGetAllForbidden() *RolesServiceGetAllForbidden {

    return &RolesServiceGetAllForbidden{}
}

// WithPayload adds the payload to the roles service get all forbidden response
func (o *RolesServiceGetAllForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *RolesServiceGetAllForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get all forbidden response
func (o *RolesServiceGetAllForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetAllForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// RolesServiceGetAllInternalServerErrorCode is the HTTP code returned for type RolesServiceGetAllInternalServerError
const RolesServiceGetAllInternalServerErrorCode int = 500

/*
RolesServiceGetAllInternalServerError Internal server error

swagger:response rolesServiceGetAllInternalServerError
*/
type RolesServiceGetAllInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewRolesServiceGetAllInternalServerError creates RolesServiceGetAllInternalServerError with default headers values
func NewRolesServiceGetAllInternalServerError() *RolesServiceGetAllInternalServerError {

    return &RolesServiceGetAllInternalServerError{}
}

// WithPayload adds the payload to the roles service get all internal server error response
func (o *RolesServiceGetAllInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *RolesServiceGetAllInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the roles service get all internal server error response
func (o *RolesServiceGetAllInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *RolesServiceGetAllInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
