// Code generated by go-swagger; DO NOT EDIT.

package authentication

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/secret-server/mock-server/models"
)

// OAuth2ServiceAuthorizeOKCode is the HTTP code returned for type OAuth2ServiceAuthorizeOK
const OAuth2ServiceAuthorizeOKCode int = 200

/*
OAuth2ServiceAuthorizeOK Successful retrieval of an access token

swagger:response oAuth2ServiceAuthorizeOK
*/
type OAuth2ServiceAuthorizeOK struct {

	/*
	  In: Body
	*/
	Payload *models.TokenResponse `json:"body,omitempty"`
}

// NewOAuth2ServiceAuthorizeOK creates OAuth2ServiceAuthorizeOK with default headers values
func NewOAuth2ServiceAuthorizeOK() *OAuth2ServiceAuthorizeOK {

	return &OAuth2ServiceAuthorizeOK{}
}

// WithPayload adds the payload to the o auth2 service authorize o k response
func (o *OAuth2ServiceAuthorizeOK) WithPayload(payload *models.TokenResponse) *OAuth2ServiceAuthorizeOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the o auth2 service authorize o k response
func (o *OAuth2ServiceAuthorizeOK) SetPayload(payload *models.TokenResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *OAuth2ServiceAuthorizeOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// OAuth2ServiceAuthorizeBadRequestCode is the HTTP code returned for type OAuth2ServiceAuthorizeBadRequest
const OAuth2ServiceAuthorizeBadRequestCode int = 400

/*
OAuth2ServiceAuthorizeBadRequest An error occurred

swagger:response oAuth2ServiceAuthorizeBadRequest
*/
type OAuth2ServiceAuthorizeBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.TokenErrorResponse `json:"body,omitempty"`
}

// NewOAuth2ServiceAuthorizeBadRequest creates OAuth2ServiceAuthorizeBadRequest with default headers values
func NewOAuth2ServiceAuthorizeBadRequest() *OAuth2ServiceAuthorizeBadRequest {

	return &OAuth2ServiceAuthorizeBadRequest{}
}

// WithPayload adds the payload to the o auth2 service authorize bad request response
func (o *OAuth2ServiceAuthorizeBadRequest) WithPayload(payload *models.TokenErrorResponse) *OAuth2ServiceAuthorizeBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the o auth2 service authorize bad request response
func (o *OAuth2ServiceAuthorizeBadRequest) SetPayload(payload *models.TokenErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *OAuth2ServiceAuthorizeBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
