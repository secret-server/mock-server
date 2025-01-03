// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "net/http"

    "github.com/go-openapi/runtime"

    "github.com/secret-server/mock-server/models"
)

// SecretsServiceUpdateListFieldListDefinitionsOKCode is the HTTP code returned for type SecretsServiceUpdateListFieldListDefinitionsOK
const SecretsServiceUpdateListFieldListDefinitionsOKCode int = 200

/*
SecretsServiceUpdateListFieldListDefinitionsOK Combined summary of all lists assigned to the secret field.

swagger:response secretsServiceUpdateListFieldListDefinitionsOK
*/
type SecretsServiceUpdateListFieldListDefinitionsOK struct {

    /*
      In: Body
    */
    Payload *models.PagingOfCategorizedListSummary `json:"body,omitempty"`
}

// NewSecretsServiceUpdateListFieldListDefinitionsOK creates SecretsServiceUpdateListFieldListDefinitionsOK with default headers values
func NewSecretsServiceUpdateListFieldListDefinitionsOK() *SecretsServiceUpdateListFieldListDefinitionsOK {

    return &SecretsServiceUpdateListFieldListDefinitionsOK{}
}

// WithPayload adds the payload to the secrets service update list field list definitions o k response
func (o *SecretsServiceUpdateListFieldListDefinitionsOK) WithPayload(payload *models.PagingOfCategorizedListSummary) *SecretsServiceUpdateListFieldListDefinitionsOK {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service update list field list definitions o k response
func (o *SecretsServiceUpdateListFieldListDefinitionsOK) SetPayload(payload *models.PagingOfCategorizedListSummary) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceUpdateListFieldListDefinitionsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(200)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceUpdateListFieldListDefinitionsBadRequestCode is the HTTP code returned for type SecretsServiceUpdateListFieldListDefinitionsBadRequest
const SecretsServiceUpdateListFieldListDefinitionsBadRequestCode int = 400

/*
SecretsServiceUpdateListFieldListDefinitionsBadRequest Bad request

swagger:response secretsServiceUpdateListFieldListDefinitionsBadRequest
*/
type SecretsServiceUpdateListFieldListDefinitionsBadRequest struct {

    /*
      In: Body
    */
    Payload *models.BadRequestResponse `json:"body,omitempty"`
}

// NewSecretsServiceUpdateListFieldListDefinitionsBadRequest creates SecretsServiceUpdateListFieldListDefinitionsBadRequest with default headers values
func NewSecretsServiceUpdateListFieldListDefinitionsBadRequest() *SecretsServiceUpdateListFieldListDefinitionsBadRequest {

    return &SecretsServiceUpdateListFieldListDefinitionsBadRequest{}
}

// WithPayload adds the payload to the secrets service update list field list definitions bad request response
func (o *SecretsServiceUpdateListFieldListDefinitionsBadRequest) WithPayload(payload *models.BadRequestResponse) *SecretsServiceUpdateListFieldListDefinitionsBadRequest {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service update list field list definitions bad request response
func (o *SecretsServiceUpdateListFieldListDefinitionsBadRequest) SetPayload(payload *models.BadRequestResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceUpdateListFieldListDefinitionsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(400)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceUpdateListFieldListDefinitionsForbiddenCode is the HTTP code returned for type SecretsServiceUpdateListFieldListDefinitionsForbidden
const SecretsServiceUpdateListFieldListDefinitionsForbiddenCode int = 403

/*
SecretsServiceUpdateListFieldListDefinitionsForbidden Authentication failed

swagger:response secretsServiceUpdateListFieldListDefinitionsForbidden
*/
type SecretsServiceUpdateListFieldListDefinitionsForbidden struct {

    /*
      In: Body
    */
    Payload *models.AuthenticationFailedResponse `json:"body,omitempty"`
}

// NewSecretsServiceUpdateListFieldListDefinitionsForbidden creates SecretsServiceUpdateListFieldListDefinitionsForbidden with default headers values
func NewSecretsServiceUpdateListFieldListDefinitionsForbidden() *SecretsServiceUpdateListFieldListDefinitionsForbidden {

    return &SecretsServiceUpdateListFieldListDefinitionsForbidden{}
}

// WithPayload adds the payload to the secrets service update list field list definitions forbidden response
func (o *SecretsServiceUpdateListFieldListDefinitionsForbidden) WithPayload(payload *models.AuthenticationFailedResponse) *SecretsServiceUpdateListFieldListDefinitionsForbidden {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service update list field list definitions forbidden response
func (o *SecretsServiceUpdateListFieldListDefinitionsForbidden) SetPayload(payload *models.AuthenticationFailedResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceUpdateListFieldListDefinitionsForbidden) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(403)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}

// SecretsServiceUpdateListFieldListDefinitionsInternalServerErrorCode is the HTTP code returned for type SecretsServiceUpdateListFieldListDefinitionsInternalServerError
const SecretsServiceUpdateListFieldListDefinitionsInternalServerErrorCode int = 500

/*
SecretsServiceUpdateListFieldListDefinitionsInternalServerError Internal server error

swagger:response secretsServiceUpdateListFieldListDefinitionsInternalServerError
*/
type SecretsServiceUpdateListFieldListDefinitionsInternalServerError struct {

    /*
      In: Body
    */
    Payload *models.InternalServerErrorResponse `json:"body,omitempty"`
}

// NewSecretsServiceUpdateListFieldListDefinitionsInternalServerError creates SecretsServiceUpdateListFieldListDefinitionsInternalServerError with default headers values
func NewSecretsServiceUpdateListFieldListDefinitionsInternalServerError() *SecretsServiceUpdateListFieldListDefinitionsInternalServerError {

    return &SecretsServiceUpdateListFieldListDefinitionsInternalServerError{}
}

// WithPayload adds the payload to the secrets service update list field list definitions internal server error response
func (o *SecretsServiceUpdateListFieldListDefinitionsInternalServerError) WithPayload(payload *models.InternalServerErrorResponse) *SecretsServiceUpdateListFieldListDefinitionsInternalServerError {
    o.Payload = payload
    return o
}

// SetPayload sets the payload to the secrets service update list field list definitions internal server error response
func (o *SecretsServiceUpdateListFieldListDefinitionsInternalServerError) SetPayload(payload *models.InternalServerErrorResponse) {
    o.Payload = payload
}

// WriteResponse to the client
func (o *SecretsServiceUpdateListFieldListDefinitionsInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

    rw.WriteHeader(500)
    if o.Payload != nil {
        payload := o.Payload
        if err := producer.Produce(rw, payload); err != nil {
            panic(err) // let the recovery middleware deal with this
        }
    }
}
