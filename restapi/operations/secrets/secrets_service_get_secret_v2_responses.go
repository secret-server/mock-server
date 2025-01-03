// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// SecretsServiceGetSecretV2OKCode is the HTTP code returned for type SecretsServiceGetSecretV2OK
const SecretsServiceGetSecretV2OKCode int = 200

/*
SecretsServiceGetSecretV2OK Secret object

swagger:response secretsServiceGetSecretV2OK
*/
type SecretsServiceGetSecretV2OK struct {

    /*
      In: Body
    */
    Payload *models.SecretModelV2 `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretV2OK creates SecretsServiceGetSecretV2OK with default headers values
func NewSecretsServiceGetSecretV2OK() *SecretsServiceGetSecretV2OK {

    return &SecretsServiceGetSecretV2OK{}
}

// WithPayload adds the payload to the secrets service get secret v2 o k response
func (o *SecretsServiceGetSecretV2OK) WithPayload(payload *models.SecretModelV2) *SecretsServiceGetSecretV2OK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get secret v2 o k response
func (o *SecretsServiceGetSecretV2OK) SetPayload(payload *models.SecretModelV2) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretV2OK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetSecretV2BadRequestCode is the HTTP code returned for type SecretsServiceGetSecretV2BadRequest
const SecretsServiceGetSecretV2BadRequestCode int = 400

/*
SecretsServiceGetSecretV2BadRequest Bad request

swagger:response secretsServiceGetSecretV2BadRequest
*/
type SecretsServiceGetSecretV2BadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretV2BadRequest creates SecretsServiceGetSecretV2BadRequest with default headers values
func NewSecretsServiceGetSecretV2BadRequest() *SecretsServiceGetSecretV2BadRequest {

    return &SecretsServiceGetSecretV2BadRequest{}
}

// WithPayload adds the payload to the secrets service get secret v2 bad request response
func (o *SecretsServiceGetSecretV2BadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceGetSecretV2BadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get secret v2 bad request response
func (o *SecretsServiceGetSecretV2BadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretV2BadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetSecretV2ForbiddenCode is the HTTP code returned for type SecretsServiceGetSecretV2Forbidden
const SecretsServiceGetSecretV2ForbiddenCode int = 403

/*
SecretsServiceGetSecretV2Forbidden Authentication failed

swagger:response secretsServiceGetSecretV2Forbidden
*/
type SecretsServiceGetSecretV2Forbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretV2Forbidden creates SecretsServiceGetSecretV2Forbidden with default headers values
func NewSecretsServiceGetSecretV2Forbidden() *SecretsServiceGetSecretV2Forbidden {

    return &SecretsServiceGetSecretV2Forbidden{}
}

// WithPayload adds the payload to the secrets service get secret v2 forbidden response
func (o *SecretsServiceGetSecretV2Forbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceGetSecretV2Forbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get secret v2 forbidden response
func (o *SecretsServiceGetSecretV2Forbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretV2Forbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetSecretV2InternalServerErrorCode is the HTTP code returned for type SecretsServiceGetSecretV2InternalServerError
const SecretsServiceGetSecretV2InternalServerErrorCode int = 500

/*
SecretsServiceGetSecretV2InternalServerError Internal server error

swagger:response secretsServiceGetSecretV2InternalServerError
*/
type SecretsServiceGetSecretV2InternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetSecretV2InternalServerError creates SecretsServiceGetSecretV2InternalServerError with default headers values
func NewSecretsServiceGetSecretV2InternalServerError() *SecretsServiceGetSecretV2InternalServerError {

    return &SecretsServiceGetSecretV2InternalServerError{}
}

// WithPayload adds the payload to the secrets service get secret v2 internal server error response
func (o *SecretsServiceGetSecretV2InternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceGetSecretV2InternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get secret v2 internal server error response
func (o *SecretsServiceGetSecretV2InternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetSecretV2InternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
