// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/secret-server/mock-server/models"
)

// SecretsServiceSearchSecretLookupOKCode is the HTTP code returned for type SecretsServiceSearchSecretLookupOK
const SecretsServiceSearchSecretLookupOKCode int = 200

/*
SecretsServiceSearchSecretLookupOK Secret search result object

swagger:response secretsServiceSearchSecretLookupOK
*/
type SecretsServiceSearchSecretLookupOK struct {

	/*
	  In: Body
	*/
	Payload *models.PagingOfSecretLookup `json:"body,omitempty"`
}

// NewSecretsServiceSearchSecretLookupOK creates SecretsServiceSearchSecretLookupOK with default headers values
func NewSecretsServiceSearchSecretLookupOK() *SecretsServiceSearchSecretLookupOK {

	return &SecretsServiceSearchSecretLookupOK{}
}

// WithPayload adds the payload to the secrets service search secret lookup o k response
func (o *SecretsServiceSearchSecretLookupOK) WithPayload(payload *models.PagingOfSecretLookup) *SecretsServiceSearchSecretLookupOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service search secret lookup o k response
func (o *SecretsServiceSearchSecretLookupOK) SetPayload(payload *models.PagingOfSecretLookup) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceSearchSecretLookupOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceSearchSecretLookupBadRequestCode is the HTTP code returned for type SecretsServiceSearchSecretLookupBadRequest
const SecretsServiceSearchSecretLookupBadRequestCode int = 400

/*
SecretsServiceSearchSecretLookupBadRequest Bad request

swagger:response secretsServiceSearchSecretLookupBadRequest
*/
type SecretsServiceSearchSecretLookupBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceSearchSecretLookupBadRequest creates SecretsServiceSearchSecretLookupBadRequest with default headers values
func NewSecretsServiceSearchSecretLookupBadRequest() *SecretsServiceSearchSecretLookupBadRequest {

	return &SecretsServiceSearchSecretLookupBadRequest{}
}

// WithPayload adds the payload to the secrets service search secret lookup bad request response
func (o *SecretsServiceSearchSecretLookupBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceSearchSecretLookupBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service search secret lookup bad request response
func (o *SecretsServiceSearchSecretLookupBadRequest) SetPayload(payload *models.BadRequestResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceSearchSecretLookupBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceSearchSecretLookupForbiddenCode is the HTTP code returned for type SecretsServiceSearchSecretLookupForbidden
const SecretsServiceSearchSecretLookupForbiddenCode int = 403

/*
SecretsServiceSearchSecretLookupForbidden Authentication failed

swagger:response secretsServiceSearchSecretLookupForbidden
*/
type SecretsServiceSearchSecretLookupForbidden struct {

	/*
	  In: Body
	*/
	Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceSearchSecretLookupForbidden creates SecretsServiceSearchSecretLookupForbidden with default headers values
func NewSecretsServiceSearchSecretLookupForbidden() *SecretsServiceSearchSecretLookupForbidden {

	return &SecretsServiceSearchSecretLookupForbidden{}
}

// WithPayload adds the payload to the secrets service search secret lookup forbidden response
func (o *SecretsServiceSearchSecretLookupForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceSearchSecretLookupForbidden {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service search secret lookup forbidden response
func (o *SecretsServiceSearchSecretLookupForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceSearchSecretLookupForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(403)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// SecretsServiceSearchSecretLookupInternalServerErrorCode is the HTTP code returned for type SecretsServiceSearchSecretLookupInternalServerError
const SecretsServiceSearchSecretLookupInternalServerErrorCode int = 500

/*
SecretsServiceSearchSecretLookupInternalServerError Internal server error

swagger:response secretsServiceSearchSecretLookupInternalServerError
*/
type SecretsServiceSearchSecretLookupInternalServerError struct {

	/*
	  In: Body
	*/
	Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceSearchSecretLookupInternalServerError creates SecretsServiceSearchSecretLookupInternalServerError with default headers values
func NewSecretsServiceSearchSecretLookupInternalServerError() *SecretsServiceSearchSecretLookupInternalServerError {

	return &SecretsServiceSearchSecretLookupInternalServerError{}
}

// WithPayload adds the payload to the secrets service search secret lookup internal server error response
func (o *SecretsServiceSearchSecretLookupInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceSearchSecretLookupInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the secrets service search secret lookup internal server error response
func (o *SecretsServiceSearchSecretLookupInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceSearchSecretLookupInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
