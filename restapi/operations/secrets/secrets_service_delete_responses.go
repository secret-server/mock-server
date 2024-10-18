// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/secret-server/mock-server/models"
)

// SecretsServiceDeleteOKCode is the HTTP code returned for type SecretsServiceDeleteOK
const SecretsServiceDeleteOKCode int = 200

/*
SecretsServiceDeleteOK Object deletion result

swagger:response secretsServiceDeleteOK
*/
type SecretsServiceDeleteOK struct {

	/*
	  In: Body
	*/
	Payload *models.DeletedModel `json:"body,omitempty"`
}

// NewSecretsServiceDeleteOK creates SecretsServiceDeleteOK with default headers values
func NewSecretsServiceDeleteOK() *SecretsServiceDeleteOK {

	return &SecretsServiceDeleteOK{}
}

// WithPayload adds the payload to the secrets service delete o k response
func (o *SecretsServiceDeleteOK) WithPayload(payload *models.DeletedModel) *SecretsServiceDeleteOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service delete o k response
func (o *SecretsServiceDeleteOK) SetPayload(payload *models.DeletedModel) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceDeleteOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceDeleteBadRequestCode is the HTTP code returned for type SecretsServiceDeleteBadRequest
const SecretsServiceDeleteBadRequestCode int = 400

/*
SecretsServiceDeleteBadRequest Bad request

swagger:response secretsServiceDeleteBadRequest
*/
type SecretsServiceDeleteBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceDeleteBadRequest creates SecretsServiceDeleteBadRequest with default headers values
func NewSecretsServiceDeleteBadRequest() *SecretsServiceDeleteBadRequest {

	return &SecretsServiceDeleteBadRequest{}
}

// WithPayload adds the payload to the secrets service delete bad request response
func (o *SecretsServiceDeleteBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceDeleteBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service delete bad request response
func (o *SecretsServiceDeleteBadRequest) SetPayload(payload *models.BadRequestResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceDeleteBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceDeleteForbiddenCode is the HTTP code returned for type SecretsServiceDeleteForbidden
const SecretsServiceDeleteForbiddenCode int = 403

/*
SecretsServiceDeleteForbidden Authentication failed

swagger:response secretsServiceDeleteForbidden
*/
type SecretsServiceDeleteForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceDeleteForbidden creates SecretsServiceDeleteForbidden with default headers values
func NewSecretsServiceDeleteForbidden() *SecretsServiceDeleteForbidden {

	return &SecretsServiceDeleteForbidden{}
}

// WithPayload adds the payload to the secrets service delete forbidden response
func (o *SecretsServiceDeleteForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceDeleteForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service delete forbidden response
func (o *SecretsServiceDeleteForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceDeleteForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceDeleteInternalServerErrorCode is the HTTP code returned for type SecretsServiceDeleteInternalServerError
const SecretsServiceDeleteInternalServerErrorCode int = 500

/*
SecretsServiceDeleteInternalServerError Internal server error

swagger:response secretsServiceDeleteInternalServerError
*/
type SecretsServiceDeleteInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceDeleteInternalServerError creates SecretsServiceDeleteInternalServerError with default headers values
func NewSecretsServiceDeleteInternalServerError() *SecretsServiceDeleteInternalServerError {

	return &SecretsServiceDeleteInternalServerError{}
}

// WithPayload adds the payload to the secrets service delete internal server error response
func (o *SecretsServiceDeleteInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceDeleteInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service delete internal server error response
func (o *SecretsServiceDeleteInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceDeleteInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}