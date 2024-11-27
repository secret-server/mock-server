// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// SecretsServiceGetRestrictedOKCode is the HTTP code returned for type SecretsServiceGetRestrictedOK
const SecretsServiceGetRestrictedOKCode int = 200

/*
SecretsServiceGetRestrictedOK Secret object

swagger:response secretsServiceGetRestrictedOK
*/
type SecretsServiceGetRestrictedOK struct {

    /*
      In: Body
    */
    Payload *models.SecretModel `json:"body,omitempty"`
}

// NewSecretsServiceGetRestrictedOK creates SecretsServiceGetRestrictedOK with default headers values
func NewSecretsServiceGetRestrictedOK() *SecretsServiceGetRestrictedOK {

    return &SecretsServiceGetRestrictedOK{}
}

// WithPayload adds the payload to the secrets service get restricted o k response
func (o *SecretsServiceGetRestrictedOK) WithPayload(payload *models.SecretModel) *SecretsServiceGetRestrictedOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get restricted o k response
func (o *SecretsServiceGetRestrictedOK) SetPayload(payload *models.SecretModel) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetRestrictedOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetRestrictedBadRequestCode is the HTTP code returned for type SecretsServiceGetRestrictedBadRequest
const SecretsServiceGetRestrictedBadRequestCode int = 400

/*
SecretsServiceGetRestrictedBadRequest Bad request

swagger:response secretsServiceGetRestrictedBadRequest
*/
type SecretsServiceGetRestrictedBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetRestrictedBadRequest creates SecretsServiceGetRestrictedBadRequest with default headers values
func NewSecretsServiceGetRestrictedBadRequest() *SecretsServiceGetRestrictedBadRequest {

    return &SecretsServiceGetRestrictedBadRequest{}
}

// WithPayload adds the payload to the secrets service get restricted bad request response
func (o *SecretsServiceGetRestrictedBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceGetRestrictedBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get restricted bad request response
func (o *SecretsServiceGetRestrictedBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetRestrictedBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetRestrictedForbiddenCode is the HTTP code returned for type SecretsServiceGetRestrictedForbidden
const SecretsServiceGetRestrictedForbiddenCode int = 403

/*
SecretsServiceGetRestrictedForbidden Authentication failed

swagger:response secretsServiceGetRestrictedForbidden
*/
type SecretsServiceGetRestrictedForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetRestrictedForbidden creates SecretsServiceGetRestrictedForbidden with default headers values
func NewSecretsServiceGetRestrictedForbidden() *SecretsServiceGetRestrictedForbidden {

    return &SecretsServiceGetRestrictedForbidden{}
}

// WithPayload adds the payload to the secrets service get restricted forbidden response
func (o *SecretsServiceGetRestrictedForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceGetRestrictedForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get restricted forbidden response
func (o *SecretsServiceGetRestrictedForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetRestrictedForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetRestrictedInternalServerErrorCode is the HTTP code returned for type SecretsServiceGetRestrictedInternalServerError
const SecretsServiceGetRestrictedInternalServerErrorCode int = 500

/*
SecretsServiceGetRestrictedInternalServerError Internal server error

swagger:response secretsServiceGetRestrictedInternalServerError
*/
type SecretsServiceGetRestrictedInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetRestrictedInternalServerError creates SecretsServiceGetRestrictedInternalServerError with default headers values
func NewSecretsServiceGetRestrictedInternalServerError() *SecretsServiceGetRestrictedInternalServerError {

    return &SecretsServiceGetRestrictedInternalServerError{}
}

// WithPayload adds the payload to the secrets service get restricted internal server error response
func (o *SecretsServiceGetRestrictedInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceGetRestrictedInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get restricted internal server error response
func (o *SecretsServiceGetRestrictedInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetRestrictedInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
