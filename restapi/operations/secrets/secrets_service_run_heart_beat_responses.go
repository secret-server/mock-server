// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// SecretsServiceRunHeartBeatOKCode is the HTTP code returned for type SecretsServiceRunHeartBeatOK
const SecretsServiceRunHeartBeatOKCode int = 200

/*
SecretsServiceRunHeartBeatOK Secret summary object

swagger:response secretsServiceRunHeartBeatOK
*/
type SecretsServiceRunHeartBeatOK struct {

    /*
      In: Body
    */
    Payload *models.SecretSummary `json:"body,omitempty"`
}

// NewSecretsServiceRunHeartBeatOK creates SecretsServiceRunHeartBeatOK with default headers values
func NewSecretsServiceRunHeartBeatOK() *SecretsServiceRunHeartBeatOK {

    return &SecretsServiceRunHeartBeatOK{}
}

// WithPayload adds the payload to the secrets service run heart beat o k response
func (o *SecretsServiceRunHeartBeatOK) WithPayload(payload *models.SecretSummary) *SecretsServiceRunHeartBeatOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service run heart beat o k response
func (o *SecretsServiceRunHeartBeatOK) SetPayload(payload *models.SecretSummary) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceRunHeartBeatOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceRunHeartBeatBadRequestCode is the HTTP code returned for type SecretsServiceRunHeartBeatBadRequest
const SecretsServiceRunHeartBeatBadRequestCode int = 400

/*
SecretsServiceRunHeartBeatBadRequest Bad request

swagger:response secretsServiceRunHeartBeatBadRequest
*/
type SecretsServiceRunHeartBeatBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceRunHeartBeatBadRequest creates SecretsServiceRunHeartBeatBadRequest with default headers values
func NewSecretsServiceRunHeartBeatBadRequest() *SecretsServiceRunHeartBeatBadRequest {

    return &SecretsServiceRunHeartBeatBadRequest{}
}

// WithPayload adds the payload to the secrets service run heart beat bad request response
func (o *SecretsServiceRunHeartBeatBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceRunHeartBeatBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service run heart beat bad request response
func (o *SecretsServiceRunHeartBeatBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceRunHeartBeatBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceRunHeartBeatForbiddenCode is the HTTP code returned for type SecretsServiceRunHeartBeatForbidden
const SecretsServiceRunHeartBeatForbiddenCode int = 403

/*
SecretsServiceRunHeartBeatForbidden Authentication failed

swagger:response secretsServiceRunHeartBeatForbidden
*/
type SecretsServiceRunHeartBeatForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceRunHeartBeatForbidden creates SecretsServiceRunHeartBeatForbidden with default headers values
func NewSecretsServiceRunHeartBeatForbidden() *SecretsServiceRunHeartBeatForbidden {

    return &SecretsServiceRunHeartBeatForbidden{}
}

// WithPayload adds the payload to the secrets service run heart beat forbidden response
func (o *SecretsServiceRunHeartBeatForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceRunHeartBeatForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service run heart beat forbidden response
func (o *SecretsServiceRunHeartBeatForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceRunHeartBeatForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceRunHeartBeatInternalServerErrorCode is the HTTP code returned for type SecretsServiceRunHeartBeatInternalServerError
const SecretsServiceRunHeartBeatInternalServerErrorCode int = 500

/*
SecretsServiceRunHeartBeatInternalServerError Internal server error

swagger:response secretsServiceRunHeartBeatInternalServerError
*/
type SecretsServiceRunHeartBeatInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceRunHeartBeatInternalServerError creates SecretsServiceRunHeartBeatInternalServerError with default headers values
func NewSecretsServiceRunHeartBeatInternalServerError() *SecretsServiceRunHeartBeatInternalServerError {

    return &SecretsServiceRunHeartBeatInternalServerError{}
}

// WithPayload adds the payload to the secrets service run heart beat internal server error response
func (o *SecretsServiceRunHeartBeatInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceRunHeartBeatInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service run heart beat internal server error response
func (o *SecretsServiceRunHeartBeatInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceRunHeartBeatInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
