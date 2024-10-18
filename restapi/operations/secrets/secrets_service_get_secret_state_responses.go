// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/secret-server/mock-server/models"
)

// SecretsServiceGetSecretStateOKCode is the HTTP code returned for type SecretsServiceGetSecretStateOK
const SecretsServiceGetSecretStateOKCode int = 200

/*
SecretsServiceGetSecretStateOK Secret Detail State View Model

swagger:response secretsServiceGetSecretStateOK
*/
type SecretsServiceGetSecretStateOK struct {

	/*
	  In: Body
	*/
	Payload *models.SecretDetailStateViewModel `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretStateOK creates SecretsServiceGetSecretStateOK with default headers values
func NewSecretsServiceGetSecretStateOK() *SecretsServiceGetSecretStateOK {

	return &SecretsServiceGetSecretStateOK{}
}

// WithPayload adds the payload to the secrets service get secret state o k response
func (o *SecretsServiceGetSecretStateOK) WithPayload(payload *models.SecretDetailStateViewModel) *SecretsServiceGetSecretStateOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service get secret state o k response
func (o *SecretsServiceGetSecretStateOK) SetPayload(payload *models.SecretDetailStateViewModel) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretStateOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceGetSecretStateBadRequestCode is the HTTP code returned for type SecretsServiceGetSecretStateBadRequest
const SecretsServiceGetSecretStateBadRequestCode int = 400

/*
SecretsServiceGetSecretStateBadRequest Bad request

swagger:response secretsServiceGetSecretStateBadRequest
*/
type SecretsServiceGetSecretStateBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretStateBadRequest creates SecretsServiceGetSecretStateBadRequest with default headers values
func NewSecretsServiceGetSecretStateBadRequest() *SecretsServiceGetSecretStateBadRequest {

	return &SecretsServiceGetSecretStateBadRequest{}
}

// WithPayload adds the payload to the secrets service get secret state bad request response
func (o *SecretsServiceGetSecretStateBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceGetSecretStateBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service get secret state bad request response
func (o *SecretsServiceGetSecretStateBadRequest) SetPayload(payload *models.BadRequestResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretStateBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceGetSecretStateForbiddenCode is the HTTP code returned for type SecretsServiceGetSecretStateForbidden
const SecretsServiceGetSecretStateForbiddenCode int = 403

/*
SecretsServiceGetSecretStateForbidden Authentication failed

swagger:response secretsServiceGetSecretStateForbidden
*/
type SecretsServiceGetSecretStateForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretStateForbidden creates SecretsServiceGetSecretStateForbidden with default headers values
func NewSecretsServiceGetSecretStateForbidden() *SecretsServiceGetSecretStateForbidden {

	return &SecretsServiceGetSecretStateForbidden{}
}

// WithPayload adds the payload to the secrets service get secret state forbidden response
func (o *SecretsServiceGetSecretStateForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceGetSecretStateForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service get secret state forbidden response
func (o *SecretsServiceGetSecretStateForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretStateForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceGetSecretStateInternalServerErrorCode is the HTTP code returned for type SecretsServiceGetSecretStateInternalServerError
const SecretsServiceGetSecretStateInternalServerErrorCode int = 500

/*
SecretsServiceGetSecretStateInternalServerError Internal server error

swagger:response secretsServiceGetSecretStateInternalServerError
*/
type SecretsServiceGetSecretStateInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretStateInternalServerError creates SecretsServiceGetSecretStateInternalServerError with default headers values
func NewSecretsServiceGetSecretStateInternalServerError() *SecretsServiceGetSecretStateInternalServerError {

	return &SecretsServiceGetSecretStateInternalServerError{}
}

// WithPayload adds the payload to the secrets service get secret state internal server error response
func (o *SecretsServiceGetSecretStateInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceGetSecretStateInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service get secret state internal server error response
func (o *SecretsServiceGetSecretStateInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretStateInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
