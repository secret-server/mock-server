// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"errors"
	"net/url"
	golangswaggerpaths "path"
	"strings"

	"github.com/go-openapi/swag"
)

// SecretsServiceGetGeneralURL generates an URL for the secrets service get general operation
type SecretsServiceGetGeneralURL struct {
	ID int32

	SecretPath *string

	_basePath string
	// avoid unkeyed usage
	_ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SecretsServiceGetGeneralURL) WithBasePath(bp string) *SecretsServiceGetGeneralURL {
	o.SetBasePath(bp)
	return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SecretsServiceGetGeneralURL) SetBasePath(bp string) {
	o._basePath = bp
}

// Build a url path and query string
func (o *SecretsServiceGetGeneralURL) Build() (*url.URL, error) {
	var _result url.URL

	var _path = "/api/v1/secrets/secret-detail/{id}/general"

	id := swag.FormatInt32(o.ID)
	if id != "" {
		_path = strings.Replace(_path, "{id}", id, -1)
	} else {
		return nil, errors.New("id is required on SecretsServiceGetGeneralURL")
	}

	_basePath := o._basePath
	if _basePath == "" {
		_basePath = "/SecretServer"
	}
	_result.Path = golangswaggerpaths.Join(_basePath, _path)

	qs := make(url.Values)

	var secretPathQ string
	if o.SecretPath != nil {
		secretPathQ = *o.SecretPath
	}
	if secretPathQ != "" {
		qs.Set("secretPath", secretPathQ)
	}

	_result.RawQuery = qs.Encode()

	return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *SecretsServiceGetGeneralURL) Must(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	if u == nil {
		panic("url can't be nil")
	}
	return u
}

// String returns the string representation of the path with query string
func (o *SecretsServiceGetGeneralURL) String() string {
	return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *SecretsServiceGetGeneralURL) BuildFull(scheme, host string) (*url.URL, error) {
	if scheme == "" {
		return nil, errors.New("scheme is required for a full url on SecretsServiceGetGeneralURL")
	}
	if host == "" {
		return nil, errors.New("host is required for a full url on SecretsServiceGetGeneralURL")
	}

	base, err := o.Build()
	if err != nil {
		return nil, err
	}

	base.Scheme = scheme
	base.Host = host
	return base, nil
}

// StringFull returns the string representation of a complete url
func (o *SecretsServiceGetGeneralURL) StringFull(scheme, host string) string {
	return o.Must(o.BuildFull(scheme, host)).String()
}
