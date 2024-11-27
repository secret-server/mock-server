// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// UsersServiceUpdateUserOKCode is the HTTP code returned for type UsersServiceUpdateUserOK
const UsersServiceUpdateUserOKCode int = 200

/*
UsersServiceUpdateUserOK User object

swagger:response usersServiceUpdateUserOK
*/
type UsersServiceUpdateUserOK struct {

    /*
      In: Body
    */
    Payload *models.UserModel `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserOK creates UsersServiceUpdateUserOK with default headers values
func NewUsersServiceUpdateUserOK() *UsersServiceUpdateUserOK {

    return &UsersServiceUpdateUserOK{}
}

// WithPayload adds the payload to the users service update user o k response
func (o *UsersServiceUpdateUserOK) WithPayload(payload *models.UserModel) *UsersServiceUpdateUserOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the users service update user o k response
func (o *UsersServiceUpdateUserOK) SetPayload(payload *models.UserModel) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// UsersServiceUpdateUserBadRequestCode is the HTTP code returned for type UsersServiceUpdateUserBadRequest
const UsersServiceUpdateUserBadRequestCode int = 400

/*
UsersServiceUpdateUserBadRequest Bad request

swagger:response usersServiceUpdateUserBadRequest
*/
type UsersServiceUpdateUserBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserBadRequest creates UsersServiceUpdateUserBadRequest with default headers values
func NewUsersServiceUpdateUserBadRequest() *UsersServiceUpdateUserBadRequest {

    return &UsersServiceUpdateUserBadRequest{}
}

// WithPayload adds the payload to the users service update user bad request response
func (o *UsersServiceUpdateUserBadRequest) WithPayload(payload *models.BadRequestResponse) *UsersServiceUpdateUserBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the users service update user bad request response
func (o *UsersServiceUpdateUserBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// UsersServiceUpdateUserForbiddenCode is the HTTP code returned for type UsersServiceUpdateUserForbidden
const UsersServiceUpdateUserForbiddenCode int = 403

/*
UsersServiceUpdateUserForbidden Authentication failed

swagger:response usersServiceUpdateUserForbidden
*/
type UsersServiceUpdateUserForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserForbidden creates UsersServiceUpdateUserForbidden with default headers values
func NewUsersServiceUpdateUserForbidden() *UsersServiceUpdateUserForbidden {

    return &UsersServiceUpdateUserForbidden{}
}

// WithPayload adds the payload to the users service update user forbidden response
func (o *UsersServiceUpdateUserForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *UsersServiceUpdateUserForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the users service update user forbidden response
func (o *UsersServiceUpdateUserForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// UsersServiceUpdateUserInternalServerErrorCode is the HTTP code returned for type UsersServiceUpdateUserInternalServerError
const UsersServiceUpdateUserInternalServerErrorCode int = 500

/*
UsersServiceUpdateUserInternalServerError Internal server error

swagger:response usersServiceUpdateUserInternalServerError
*/
type UsersServiceUpdateUserInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserInternalServerError creates UsersServiceUpdateUserInternalServerError with default headers values
func NewUsersServiceUpdateUserInternalServerError() *UsersServiceUpdateUserInternalServerError {

    return &UsersServiceUpdateUserInternalServerError{}
}

// WithPayload adds the payload to the users service update user internal server error response
func (o *UsersServiceUpdateUserInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *UsersServiceUpdateUserInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the users service update user internal server error response
func (o *UsersServiceUpdateUserInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
