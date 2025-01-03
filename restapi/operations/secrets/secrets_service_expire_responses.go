// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// SecretsServiceExpireOKCode is the HTTP code returned for type SecretsServiceExpireOK
const SecretsServiceExpireOKCode int = 200

/*
SecretsServiceExpireOK Secret summary object

swagger:response secretsServiceExpireOK
*/
type SecretsServiceExpireOK struct {

    /*
      In: Body
    */
    Payload *models.SecretSummary `json:"body,omitempty"`
}

// NewSecretsServiceExpireOK creates SecretsServiceExpireOK with default headers values
func NewSecretsServiceExpireOK() *SecretsServiceExpireOK {

    return &SecretsServiceExpireOK{}
}

// WithPayload adds the payload to the secrets service expire o k response
func (o *SecretsServiceExpireOK) WithPayload(payload *models.SecretSummary) *SecretsServiceExpireOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service expire o k response
func (o *SecretsServiceExpireOK) SetPayload(payload *models.SecretSummary) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceExpireOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceExpireBadRequestCode is the HTTP code returned for type SecretsServiceExpireBadRequest
const SecretsServiceExpireBadRequestCode int = 400

/*
SecretsServiceExpireBadRequest Bad request

swagger:response secretsServiceExpireBadRequest
*/
type SecretsServiceExpireBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceExpireBadRequest creates SecretsServiceExpireBadRequest with default headers values
func NewSecretsServiceExpireBadRequest() *SecretsServiceExpireBadRequest {

    return &SecretsServiceExpireBadRequest{}
}

// WithPayload adds the payload to the secrets service expire bad request response
func (o *SecretsServiceExpireBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceExpireBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service expire bad request response
func (o *SecretsServiceExpireBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceExpireBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceExpireForbiddenCode is the HTTP code returned for type SecretsServiceExpireForbidden
const SecretsServiceExpireForbiddenCode int = 403

/*
SecretsServiceExpireForbidden Authentication failed

swagger:response secretsServiceExpireForbidden
*/
type SecretsServiceExpireForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceExpireForbidden creates SecretsServiceExpireForbidden with default headers values
func NewSecretsServiceExpireForbidden() *SecretsServiceExpireForbidden {

    return &SecretsServiceExpireForbidden{}
}

// WithPayload adds the payload to the secrets service expire forbidden response
func (o *SecretsServiceExpireForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceExpireForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service expire forbidden response
func (o *SecretsServiceExpireForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceExpireForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceExpireInternalServerErrorCode is the HTTP code returned for type SecretsServiceExpireInternalServerError
const SecretsServiceExpireInternalServerErrorCode int = 500

/*
SecretsServiceExpireInternalServerError Internal server error

swagger:response secretsServiceExpireInternalServerError
*/
type SecretsServiceExpireInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceExpireInternalServerError creates SecretsServiceExpireInternalServerError with default headers values
func NewSecretsServiceExpireInternalServerError() *SecretsServiceExpireInternalServerError {

    return &SecretsServiceExpireInternalServerError{}
}

// WithPayload adds the payload to the secrets service expire internal server error response
func (o *SecretsServiceExpireInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceExpireInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service expire internal server error response
func (o *SecretsServiceExpireInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceExpireInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
