// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/secret-server/mock-server/models"
)

// UsersServiceUpdateUserRolesOKCode is the HTTP code returned for type UsersServiceUpdateUserRolesOK
const UsersServiceUpdateUserRolesOKCode int = 200

/*
UsersServiceUpdateUserRolesOK Success / Fail

swagger:response usersServiceUpdateUserRolesOK
*/
type UsersServiceUpdateUserRolesOK struct {

	/*
	  In: Body
	*/
	Payload *models.RoleChangeStatusModel `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserRolesOK creates UsersServiceUpdateUserRolesOK with default headers values
func NewUsersServiceUpdateUserRolesOK() *UsersServiceUpdateUserRolesOK {

	return &UsersServiceUpdateUserRolesOK{}
}

// WithPayload adds the payload to the users service update user roles o k response
func (o *UsersServiceUpdateUserRolesOK) WithPayload(payload *models.RoleChangeStatusModel) *UsersServiceUpdateUserRolesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the users service update user roles o k response
func (o *UsersServiceUpdateUserRolesOK) SetPayload(payload *models.RoleChangeStatusModel) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserRolesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UsersServiceUpdateUserRolesBadRequestCode is the HTTP code returned for type UsersServiceUpdateUserRolesBadRequest
const UsersServiceUpdateUserRolesBadRequestCode int = 400

/*
UsersServiceUpdateUserRolesBadRequest Bad request

swagger:response usersServiceUpdateUserRolesBadRequest
*/
type UsersServiceUpdateUserRolesBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserRolesBadRequest creates UsersServiceUpdateUserRolesBadRequest with default headers values
func NewUsersServiceUpdateUserRolesBadRequest() *UsersServiceUpdateUserRolesBadRequest {

	return &UsersServiceUpdateUserRolesBadRequest{}
}

// WithPayload adds the payload to the users service update user roles bad request response
func (o *UsersServiceUpdateUserRolesBadRequest) WithPayload(payload *models.BadRequestResponse) *UsersServiceUpdateUserRolesBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the users service update user roles bad request response
func (o *UsersServiceUpdateUserRolesBadRequest) SetPayload(payload *models.BadRequestResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserRolesBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UsersServiceUpdateUserRolesForbiddenCode is the HTTP code returned for type UsersServiceUpdateUserRolesForbidden
const UsersServiceUpdateUserRolesForbiddenCode int = 403

/*
UsersServiceUpdateUserRolesForbidden Authentication failed

swagger:response usersServiceUpdateUserRolesForbidden
*/
type UsersServiceUpdateUserRolesForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserRolesForbidden creates UsersServiceUpdateUserRolesForbidden with default headers values
func NewUsersServiceUpdateUserRolesForbidden() *UsersServiceUpdateUserRolesForbidden {

	return &UsersServiceUpdateUserRolesForbidden{}
}

// WithPayload adds the payload to the users service update user roles forbidden response
func (o *UsersServiceUpdateUserRolesForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *UsersServiceUpdateUserRolesForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the users service update user roles forbidden response
func (o *UsersServiceUpdateUserRolesForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserRolesForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UsersServiceUpdateUserRolesInternalServerErrorCode is the HTTP code returned for type UsersServiceUpdateUserRolesInternalServerError
const UsersServiceUpdateUserRolesInternalServerErrorCode int = 500

/*
UsersServiceUpdateUserRolesInternalServerError Internal server error

swagger:response usersServiceUpdateUserRolesInternalServerError
*/
type UsersServiceUpdateUserRolesInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewUsersServiceUpdateUserRolesInternalServerError creates UsersServiceUpdateUserRolesInternalServerError with default headers values
func NewUsersServiceUpdateUserRolesInternalServerError() *UsersServiceUpdateUserRolesInternalServerError {

	return &UsersServiceUpdateUserRolesInternalServerError{}
}

// WithPayload adds the payload to the users service update user roles internal server error response
func (o *UsersServiceUpdateUserRolesInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *UsersServiceUpdateUserRolesInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the users service update user roles internal server error response
func (o *UsersServiceUpdateUserRolesInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UsersServiceUpdateUserRolesInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
