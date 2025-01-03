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

// SecretsServiceGetListFieldListDefinitionsURL generates an URL for the secrets service get list field list definitions operation
type SecretsServiceGetListFieldListDefinitionsURL struct {
    ID   int32
    Slug string

    AutoCheckIn      *bool
    AutoCheckout     *bool
    AutoComment      *string
    ForceCheckIn     *bool
    Skip             *int32
    SortBy0Direction *string
    SortBy0Name      *string
    SortBy0Priority  *int32
    Take             *int32

    _basePath string
    // avoid unkeyed usage
    _ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SecretsServiceGetListFieldListDefinitionsURL) WithBasePath(bp string) *SecretsServiceGetListFieldListDefinitionsURL {
    o.SetBasePath(bp)
    return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SecretsServiceGetListFieldListDefinitionsURL) SetBasePath(bp string) {
    o._basePath = bp
}

// Build a url path and query string
func (o *SecretsServiceGetListFieldListDefinitionsURL) Build() (*url.URL, error) {
    var _result url.URL

    var _path = "/api/v1/secrets/{id}/fields/{slug}/listdetails"

    id := swag.FormatInt32(o.ID)
    if id != "" {
        _path = strings.Replace(_path, "{id}", id, -1)
    } else {
        return nil, errors.New("id is required on SecretsServiceGetListFieldListDefinitionsURL")
    }

    slug := o.Slug
    if slug != "" {
        _path = strings.Replace(_path, "{slug}", slug, -1)
    } else {
        return nil, errors.New("slug is required on SecretsServiceGetListFieldListDefinitionsURL")
    }

    _basePath := o._basePath
    if _basePath == "" {
        _basePath = "/SecretServer"
    }
    _result.Path = golangswaggerpaths.Join(_basePath, _path)

    qs := make(url.Values)

    var autoCheckInQ string
    if o.AutoCheckIn != nil {
        autoCheckInQ = swag.FormatBool(*o.AutoCheckIn)
    }
    if autoCheckInQ != "" {
        qs.Set("autoCheckIn", autoCheckInQ)
    }

    var autoCheckoutQ string
    if o.AutoCheckout != nil {
        autoCheckoutQ = swag.FormatBool(*o.AutoCheckout)
    }
    if autoCheckoutQ != "" {
        qs.Set("autoCheckout", autoCheckoutQ)
    }

    var autoCommentQ string
    if o.AutoComment != nil {
        autoCommentQ = *o.AutoComment
    }
    if autoCommentQ != "" {
        qs.Set("autoComment", autoCommentQ)
    }

    var forceCheckInQ string
    if o.ForceCheckIn != nil {
        forceCheckInQ = swag.FormatBool(*o.ForceCheckIn)
    }
    if forceCheckInQ != "" {
        qs.Set("forceCheckIn", forceCheckInQ)
    }

    var skipQ string
    if o.Skip != nil {
        skipQ = swag.FormatInt32(*o.Skip)
    }
    if skipQ != "" {
        qs.Set("skip", skipQ)
    }

    var sortBy0DirectionQ string
    if o.SortBy0Direction != nil {
        sortBy0DirectionQ = *o.SortBy0Direction
    }
    if sortBy0DirectionQ != "" {
        qs.Set("sortBy[0].direction", sortBy0DirectionQ)
    }

    var sortBy0NameQ string
    if o.SortBy0Name != nil {
        sortBy0NameQ = *o.SortBy0Name
    }
    if sortBy0NameQ != "" {
        qs.Set("sortBy[0].name", sortBy0NameQ)
    }

    var sortBy0PriorityQ string
    if o.SortBy0Priority != nil {
        sortBy0PriorityQ = swag.FormatInt32(*o.SortBy0Priority)
    }
    if sortBy0PriorityQ != "" {
        qs.Set("sortBy[0].priority", sortBy0PriorityQ)
    }

    var takeQ string
    if o.Take != nil {
        takeQ = swag.FormatInt32(*o.Take)
    }
    if takeQ != "" {
        qs.Set("take", takeQ)
    }

    _result.RawQuery = qs.Encode()

    return &_result, nil
}

// Must is a helper function to panic when the url builder returns an error
func (o *SecretsServiceGetListFieldListDefinitionsURL) Must(u *url.URL, err error) *url.URL {
    if err != nil {
        panic(err)
    }
    if u == nil {
        panic("url can't be nil")
    }
    return u
}

// String returns the string representation of the path with query string
func (o *SecretsServiceGetListFieldListDefinitionsURL) String() string {
    return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *SecretsServiceGetListFieldListDefinitionsURL) BuildFull(scheme, host string) (*url.URL, error) {
    if scheme == "" {
        return nil, errors.New("scheme is required for a full url on SecretsServiceGetListFieldListDefinitionsURL")
    }
    if host == "" {
        return nil, errors.New("host is required for a full url on SecretsServiceGetListFieldListDefinitionsURL")
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
func (o *SecretsServiceGetListFieldListDefinitionsURL) StringFull(scheme, host string) string {
    return o.Must(o.BuildFull(scheme, host)).String()
}
