// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// SecretsServiceGetGeneralOKCode is the HTTP code returned for type SecretsServiceGetGeneralOK
const SecretsServiceGetGeneralOKCode int = 200

/*
SecretsServiceGetGeneralOK Secret Detail State View Model

swagger:response secretsServiceGetGeneralOK
*/
type SecretsServiceGetGeneralOK struct {

    /*Secret Detail State View Model
      In: Body
    */
    Payload *models.SecretDetailGeneralModel `json:"body,omitempty"`
}

// NewSecretsServiceGetGeneralOK creates SecretsServiceGetGeneralOK with default headers values
func NewSecretsServiceGetGeneralOK() *SecretsServiceGetGeneralOK {

    return &SecretsServiceGetGeneralOK{}
}

// WithPayload adds the payload to the secrets service get general o k response
func (o *SecretsServiceGetGeneralOK) WithPayload(payload *models.SecretDetailGeneralModel) *SecretsServiceGetGeneralOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get general o k response
func (o *SecretsServiceGetGeneralOK) SetPayload(payload *models.SecretDetailGeneralModel) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetGeneralOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetGeneralBadRequestCode is the HTTP code returned for type SecretsServiceGetGeneralBadRequest
const SecretsServiceGetGeneralBadRequestCode int = 400

/*
SecretsServiceGetGeneralBadRequest Bad request

swagger:response secretsServiceGetGeneralBadRequest
*/
type SecretsServiceGetGeneralBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetGeneralBadRequest creates SecretsServiceGetGeneralBadRequest with default headers values
func NewSecretsServiceGetGeneralBadRequest() *SecretsServiceGetGeneralBadRequest {

    return &SecretsServiceGetGeneralBadRequest{}
}

// WithPayload adds the payload to the secrets service get general bad request response
func (o *SecretsServiceGetGeneralBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceGetGeneralBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get general bad request response
func (o *SecretsServiceGetGeneralBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetGeneralBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetGeneralForbiddenCode is the HTTP code returned for type SecretsServiceGetGeneralForbidden
const SecretsServiceGetGeneralForbiddenCode int = 403

/*
SecretsServiceGetGeneralForbidden Authentication failed

swagger:response secretsServiceGetGeneralForbidden
*/
type SecretsServiceGetGeneralForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetGeneralForbidden creates SecretsServiceGetGeneralForbidden with default headers values
func NewSecretsServiceGetGeneralForbidden() *SecretsServiceGetGeneralForbidden {

    return &SecretsServiceGetGeneralForbidden{}
}

// WithPayload adds the payload to the secrets service get general forbidden response
func (o *SecretsServiceGetGeneralForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceGetGeneralForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get general forbidden response
func (o *SecretsServiceGetGeneralForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetGeneralForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceGetGeneralInternalServerErrorCode is the HTTP code returned for type SecretsServiceGetGeneralInternalServerError
const SecretsServiceGetGeneralInternalServerErrorCode int = 500

/*
SecretsServiceGetGeneralInternalServerError Internal server error

swagger:response secretsServiceGetGeneralInternalServerError
*/
type SecretsServiceGetGeneralInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceGetGeneralInternalServerError creates SecretsServiceGetGeneralInternalServerError with default headers values
func NewSecretsServiceGetGeneralInternalServerError() *SecretsServiceGetGeneralInternalServerError {

    return &SecretsServiceGetGeneralInternalServerError{}
}

// WithPayload adds the payload to the secrets service get general internal server error response
func (o *SecretsServiceGetGeneralInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceGetGeneralInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service get general internal server error response
func (o *SecretsServiceGetGeneralInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceGetGeneralInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
