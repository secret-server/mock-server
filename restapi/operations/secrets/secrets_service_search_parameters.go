// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
    "fmt"
    "net/http"

    "github.com/go-openapi/errors"
    "github.com/go-openapi/runtime"
    "github.com/go-openapi/runtime/middleware"
    "github.com/go-openapi/strfmt"
    "github.com/go-openapi/swag"
)

// NewSecretsServiceSearchParams creates a new SecretsServiceSearchParams object
//
// There are no default values defined in the spec.
func NewSecretsServiceSearchParams() SecretsServiceSearchParams {

    return SecretsServiceSearchParams{}
}

// SecretsServiceSearchParams contains all the bound params for the secrets service search operation
// typically these are obtained from a http.Request
//
// swagger:parameters SecretsService_Search
type SecretsServiceSearchParams struct {

    // HTTP Request Object
    HTTPRequest *http.Request `json:"-"`

    /*Whether to allow DoubleLocks as part of the search. True by default.
      In: query
    */
    FilterAllowDoubleLocks *bool
    /*Whether to return the total number of secrets matching the filters. False by default. If false, the total can be retrieved separately by calling   /api/v1/secrets/search-total with the same arguments used in the search.
      In: query
    */
    FilterDoNotCalculateTotal *bool
    /*Only include Secrets with this DoubleLock ID assigned in the search results.
      In: query
    */
    FilterDoubleLockID *int32
    /*An array of names of Secret Template fields to return.  Only exposed fields can be returned.
      In: query
      Collection Format: multi
    */
    FilterExtendedFields []string
    /*If not null, return only secrets matching the specified extended mapping type as defined on the secret’s template.
      In: query
    */
    FilterExtendedTypeID *int32
    /*If not null, returns only secrets within the specified folder.
      In: query
    */
    FilterFolderID *int32
    /*If not null, returns only secrets with a certain heartbeat status.
      In: query
    */
    FilterHeartbeatStatus *string
    /*Whether to include active secrets in results (when excluded equals true).
      In: query
    */
    FilterIncludeActive *bool
    /*Whether to include inactive secrets in results.
      In: query
    */
    FilterIncludeInactive *bool
    /*Whether to include restricted secrets in results. Restricted secrets are secrets that are DoubleLocked, require approval, or require a comment to view.
      In: query
    */
    FilterIncludeRestricted *bool
    /*Whether to include secrets in subfolders of the specified folder.
      In: query
    */
    FilterIncludeSubFolders *bool
    /*Whether to do an exact match of the search text or a partial match. If an exact match, the entire secret name, field value, or list option in a list field must match the search text.
      In: query
    */
    FilterIsExactMatch *bool
    /*Whether to only include secrets whose template has Remote Password Changing enabled.
      In: query
    */
    FilterOnlyRPCEnabled *bool
    /*When true only Secrets where you are not the owner and the Secret was shared explicitly with your user id will be returned.
      In: query
    */
    FilterOnlySharedWithMe *bool
    /*If not null, returns only secrets matching the specified password types.
      In: query
      Collection Format: multi
    */
    FilterPasswordTypeIds []int64
    /*Specify whether to filter by List, View, Edit, or Owner permission. Default is List.
      In: query
    */
    FilterPermissionRequired *string
    /*Specify whether to search All, Recent, or Favorites
      In: query
    */
    FilterScope *string
    /*If set, restricts the search to only match secrets where the value of the field specified by name contains the search text.
      In: query
    */
    FilterSearchField *string
    /*If set, restricts the search to only match secrets where the value of the field specified by the slug name contains the search text. This will override SearchField.
      In: query
    */
    FilterSearchFieldSlug *string
    /*The text to match in the secret name, field value, or list field contents.
      In: query
    */
    FilterSearchText *string
    /*If not null, returns only secrets matching the specified template.
      In: query
    */
    FilterSecretTemplateID *int32
    /*If not null, returns only secrets within a the specified site.
      In: query
    */
    FilterSiteID *int32
    /*Number of records to skip before taking results
      In: query
    */
    Skip *int32
    /*Sort direction
      In: query
    */
    SortBy0Direction *string
    /*Sort field name
      In: query
    */
    SortBy0Name *string
    /*Priority index. Sorts with lower values are executed earlier
      In: query
    */
    SortBy0Priority *int32
    /*Maximum number of records to include in results
      In: query
    */
    Take *int32
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewSecretsServiceSearchParams() beforehand.
func (o *SecretsServiceSearchParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
    var res []error

    o.HTTPRequest = r

    qs := runtime.Values(r.URL.Query())

    qFilterAllowDoubleLocks, qhkFilterAllowDoubleLocks, _ := qs.GetOK("filter.allowDoubleLocks")
    if err := o.bindFilterAllowDoubleLocks(qFilterAllowDoubleLocks, qhkFilterAllowDoubleLocks, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterDoNotCalculateTotal, qhkFilterDoNotCalculateTotal, _ := qs.GetOK("filter.doNotCalculateTotal")
    if err := o.bindFilterDoNotCalculateTotal(qFilterDoNotCalculateTotal, qhkFilterDoNotCalculateTotal, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterDoubleLockID, qhkFilterDoubleLockID, _ := qs.GetOK("filter.doubleLockId")
    if err := o.bindFilterDoubleLockID(qFilterDoubleLockID, qhkFilterDoubleLockID, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterExtendedFields, qhkFilterExtendedFields, _ := qs.GetOK("filter.extendedFields")
    if err := o.bindFilterExtendedFields(qFilterExtendedFields, qhkFilterExtendedFields, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterExtendedTypeID, qhkFilterExtendedTypeID, _ := qs.GetOK("filter.extendedTypeId")
    if err := o.bindFilterExtendedTypeID(qFilterExtendedTypeID, qhkFilterExtendedTypeID, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterFolderID, qhkFilterFolderID, _ := qs.GetOK("filter.folderId")
    if err := o.bindFilterFolderID(qFilterFolderID, qhkFilterFolderID, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterHeartbeatStatus, qhkFilterHeartbeatStatus, _ := qs.GetOK("filter.heartbeatStatus")
    if err := o.bindFilterHeartbeatStatus(qFilterHeartbeatStatus, qhkFilterHeartbeatStatus, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterIncludeActive, qhkFilterIncludeActive, _ := qs.GetOK("filter.includeActive")
    if err := o.bindFilterIncludeActive(qFilterIncludeActive, qhkFilterIncludeActive, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterIncludeInactive, qhkFilterIncludeInactive, _ := qs.GetOK("filter.includeInactive")
    if err := o.bindFilterIncludeInactive(qFilterIncludeInactive, qhkFilterIncludeInactive, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterIncludeRestricted, qhkFilterIncludeRestricted, _ := qs.GetOK("filter.includeRestricted")
    if err := o.bindFilterIncludeRestricted(qFilterIncludeRestricted, qhkFilterIncludeRestricted, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterIncludeSubFolders, qhkFilterIncludeSubFolders, _ := qs.GetOK("filter.includeSubFolders")
    if err := o.bindFilterIncludeSubFolders(qFilterIncludeSubFolders, qhkFilterIncludeSubFolders, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterIsExactMatch, qhkFilterIsExactMatch, _ := qs.GetOK("filter.isExactMatch")
    if err := o.bindFilterIsExactMatch(qFilterIsExactMatch, qhkFilterIsExactMatch, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterOnlyRPCEnabled, qhkFilterOnlyRPCEnabled, _ := qs.GetOK("filter.onlyRPCEnabled")
    if err := o.bindFilterOnlyRPCEnabled(qFilterOnlyRPCEnabled, qhkFilterOnlyRPCEnabled, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterOnlySharedWithMe, qhkFilterOnlySharedWithMe, _ := qs.GetOK("filter.onlySharedWithMe")
    if err := o.bindFilterOnlySharedWithMe(qFilterOnlySharedWithMe, qhkFilterOnlySharedWithMe, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterPasswordTypeIds, qhkFilterPasswordTypeIds, _ := qs.GetOK("filter.passwordTypeIds")
    if err := o.bindFilterPasswordTypeIds(qFilterPasswordTypeIds, qhkFilterPasswordTypeIds, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterPermissionRequired, qhkFilterPermissionRequired, _ := qs.GetOK("filter.permissionRequired")
    if err := o.bindFilterPermissionRequired(qFilterPermissionRequired, qhkFilterPermissionRequired, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterScope, qhkFilterScope, _ := qs.GetOK("filter.scope")
    if err := o.bindFilterScope(qFilterScope, qhkFilterScope, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterSearchField, qhkFilterSearchField, _ := qs.GetOK("filter.searchField")
    if err := o.bindFilterSearchField(qFilterSearchField, qhkFilterSearchField, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterSearchFieldSlug, qhkFilterSearchFieldSlug, _ := qs.GetOK("filter.searchFieldSlug")
    if err := o.bindFilterSearchFieldSlug(qFilterSearchFieldSlug, qhkFilterSearchFieldSlug, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterSearchText, qhkFilterSearchText, _ := qs.GetOK("filter.searchText")
    if err := o.bindFilterSearchText(qFilterSearchText, qhkFilterSearchText, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterSecretTemplateID, qhkFilterSecretTemplateID, _ := qs.GetOK("filter.secretTemplateId")
    if err := o.bindFilterSecretTemplateID(qFilterSecretTemplateID, qhkFilterSecretTemplateID, route.Formats); err != nil {
        res = append(res, err)
    }

    qFilterSiteID, qhkFilterSiteID, _ := qs.GetOK("filter.siteId")
    if err := o.bindFilterSiteID(qFilterSiteID, qhkFilterSiteID, route.Formats); err != nil {
        res = append(res, err)
    }

    qSkip, qhkSkip, _ := qs.GetOK("skip")
    if err := o.bindSkip(qSkip, qhkSkip, route.Formats); err != nil {
        res = append(res, err)
    }

    qSortBy0Direction, qhkSortBy0Direction, _ := qs.GetOK("sortBy[0].direction")
    if err := o.bindSortBy0Direction(qSortBy0Direction, qhkSortBy0Direction, route.Formats); err != nil {
        res = append(res, err)
    }

    qSortBy0Name, qhkSortBy0Name, _ := qs.GetOK("sortBy[0].name")
    if err := o.bindSortBy0Name(qSortBy0Name, qhkSortBy0Name, route.Formats); err != nil {
        res = append(res, err)
    }

    qSortBy0Priority, qhkSortBy0Priority, _ := qs.GetOK("sortBy[0].priority")
    if err := o.bindSortBy0Priority(qSortBy0Priority, qhkSortBy0Priority, route.Formats); err != nil {
        res = append(res, err)
    }

    qTake, qhkTake, _ := qs.GetOK("take")
    if err := o.bindTake(qTake, qhkTake, route.Formats); err != nil {
        res = append(res, err)
    }
    if len(res) > 0 {
        return errors.CompositeValidationError(res...)
    }
    return nil
}

// bindFilterAllowDoubleLocks binds and validates parameter FilterAllowDoubleLocks from query.
func (o *SecretsServiceSearchParams) bindFilterAllowDoubleLocks(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.allowDoubleLocks", "query", "bool", raw)
    }
    o.FilterAllowDoubleLocks = &value

    return nil
}

// bindFilterDoNotCalculateTotal binds and validates parameter FilterDoNotCalculateTotal from query.
func (o *SecretsServiceSearchParams) bindFilterDoNotCalculateTotal(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.doNotCalculateTotal", "query", "bool", raw)
    }
    o.FilterDoNotCalculateTotal = &value

    return nil
}

// bindFilterDoubleLockID binds and validates parameter FilterDoubleLockID from query.
func (o *SecretsServiceSearchParams) bindFilterDoubleLockID(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("filter.doubleLockId", "query", "int32", raw)
    }
    o.FilterDoubleLockID = &value

    return nil
}

// bindFilterExtendedFields binds and validates array parameter FilterExtendedFields from query.
//
// Arrays are parsed according to CollectionFormat: "multi" (defaults to "csv" when empty).
func (o *SecretsServiceSearchParams) bindFilterExtendedFields(rawData []string, hasKey bool, formats strfmt.Registry) error {
    // CollectionFormat: multi
    filterExtendedFieldsIC := rawData
    if len(filterExtendedFieldsIC) == 0 {
        return nil
    }

    var filterExtendedFieldsIR []string
    for _, filterExtendedFieldsIV := range filterExtendedFieldsIC {
        filterExtendedFieldsI := filterExtendedFieldsIV

        filterExtendedFieldsIR = append(filterExtendedFieldsIR, filterExtendedFieldsI)
    }

    o.FilterExtendedFields = filterExtendedFieldsIR

    return nil
}

// bindFilterExtendedTypeID binds and validates parameter FilterExtendedTypeID from query.
func (o *SecretsServiceSearchParams) bindFilterExtendedTypeID(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("filter.extendedTypeId", "query", "int32", raw)
    }
    o.FilterExtendedTypeID = &value

    return nil
}

// bindFilterFolderID binds and validates parameter FilterFolderID from query.
func (o *SecretsServiceSearchParams) bindFilterFolderID(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("filter.folderId", "query", "int32", raw)
    }
    o.FilterFolderID = &value

    return nil
}

// bindFilterHeartbeatStatus binds and validates parameter FilterHeartbeatStatus from query.
func (o *SecretsServiceSearchParams) bindFilterHeartbeatStatus(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.FilterHeartbeatStatus = &raw

    return nil
}

// bindFilterIncludeActive binds and validates parameter FilterIncludeActive from query.
func (o *SecretsServiceSearchParams) bindFilterIncludeActive(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.includeActive", "query", "bool", raw)
    }
    o.FilterIncludeActive = &value

    return nil
}

// bindFilterIncludeInactive binds and validates parameter FilterIncludeInactive from query.
func (o *SecretsServiceSearchParams) bindFilterIncludeInactive(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.includeInactive", "query", "bool", raw)
    }
    o.FilterIncludeInactive = &value

    return nil
}

// bindFilterIncludeRestricted binds and validates parameter FilterIncludeRestricted from query.
func (o *SecretsServiceSearchParams) bindFilterIncludeRestricted(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.includeRestricted", "query", "bool", raw)
    }
    o.FilterIncludeRestricted = &value

    return nil
}

// bindFilterIncludeSubFolders binds and validates parameter FilterIncludeSubFolders from query.
func (o *SecretsServiceSearchParams) bindFilterIncludeSubFolders(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.includeSubFolders", "query", "bool", raw)
    }
    o.FilterIncludeSubFolders = &value

    return nil
}

// bindFilterIsExactMatch binds and validates parameter FilterIsExactMatch from query.
func (o *SecretsServiceSearchParams) bindFilterIsExactMatch(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.isExactMatch", "query", "bool", raw)
    }
    o.FilterIsExactMatch = &value

    return nil
}

// bindFilterOnlyRPCEnabled binds and validates parameter FilterOnlyRPCEnabled from query.
func (o *SecretsServiceSearchParams) bindFilterOnlyRPCEnabled(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.onlyRPCEnabled", "query", "bool", raw)
    }
    o.FilterOnlyRPCEnabled = &value

    return nil
}

// bindFilterOnlySharedWithMe binds and validates parameter FilterOnlySharedWithMe from query.
func (o *SecretsServiceSearchParams) bindFilterOnlySharedWithMe(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertBool(raw)
    if err != nil {
        return errors.InvalidType("filter.onlySharedWithMe", "query", "bool", raw)
    }
    o.FilterOnlySharedWithMe = &value

    return nil
}

// bindFilterPasswordTypeIds binds and validates array parameter FilterPasswordTypeIds from query.
//
// Arrays are parsed according to CollectionFormat: "multi" (defaults to "csv" when empty).
func (o *SecretsServiceSearchParams) bindFilterPasswordTypeIds(rawData []string, hasKey bool, formats strfmt.Registry) error {
    // CollectionFormat: multi
    filterPasswordTypeIdsIC := rawData
    if len(filterPasswordTypeIdsIC) == 0 {
        return nil
    }

    var filterPasswordTypeIdsIR []int64
    for i, filterPasswordTypeIdsIV := range filterPasswordTypeIdsIC {
        filterPasswordTypeIdsI, err := swag.ConvertInt64(filterPasswordTypeIdsIV)
        if err != nil {
            return errors.InvalidType(fmt.Sprintf("%s.%v", "filter.passwordTypeIds", i), "query", "int64", filterPasswordTypeIdsI)
        }

        filterPasswordTypeIdsIR = append(filterPasswordTypeIdsIR, filterPasswordTypeIdsI)
    }

    o.FilterPasswordTypeIds = filterPasswordTypeIdsIR

    return nil
}

// bindFilterPermissionRequired binds and validates parameter FilterPermissionRequired from query.
func (o *SecretsServiceSearchParams) bindFilterPermissionRequired(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.FilterPermissionRequired = &raw

    return nil
}

// bindFilterScope binds and validates parameter FilterScope from query.
func (o *SecretsServiceSearchParams) bindFilterScope(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.FilterScope = &raw

    return nil
}

// bindFilterSearchField binds and validates parameter FilterSearchField from query.
func (o *SecretsServiceSearchParams) bindFilterSearchField(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.FilterSearchField = &raw

    return nil
}

// bindFilterSearchFieldSlug binds and validates parameter FilterSearchFieldSlug from query.
func (o *SecretsServiceSearchParams) bindFilterSearchFieldSlug(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.FilterSearchFieldSlug = &raw

    return nil
}

// bindFilterSearchText binds and validates parameter FilterSearchText from query.
func (o *SecretsServiceSearchParams) bindFilterSearchText(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.FilterSearchText = &raw

    return nil
}

// bindFilterSecretTemplateID binds and validates parameter FilterSecretTemplateID from query.
func (o *SecretsServiceSearchParams) bindFilterSecretTemplateID(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("filter.secretTemplateId", "query", "int32", raw)
    }
    o.FilterSecretTemplateID = &value

    return nil
}

// bindFilterSiteID binds and validates parameter FilterSiteID from query.
func (o *SecretsServiceSearchParams) bindFilterSiteID(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("filter.siteId", "query", "int32", raw)
    }
    o.FilterSiteID = &value

    return nil
}

// bindSkip binds and validates parameter Skip from query.
func (o *SecretsServiceSearchParams) bindSkip(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("skip", "query", "int32", raw)
    }
    o.Skip = &value

    return nil
}

// bindSortBy0Direction binds and validates parameter SortBy0Direction from query.
func (o *SecretsServiceSearchParams) bindSortBy0Direction(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.SortBy0Direction = &raw

    return nil
}

// bindSortBy0Name binds and validates parameter SortBy0Name from query.
func (o *SecretsServiceSearchParams) bindSortBy0Name(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }
    o.SortBy0Name = &raw

    return nil
}

// bindSortBy0Priority binds and validates parameter SortBy0Priority from query.
func (o *SecretsServiceSearchParams) bindSortBy0Priority(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("sortBy[0].priority", "query", "int32", raw)
    }
    o.SortBy0Priority = &value

    return nil
}

// bindTake binds and validates parameter Take from query.
func (o *SecretsServiceSearchParams) bindTake(rawData []string, hasKey bool, formats strfmt.Registry) error {
    var raw string
    if len(rawData) > 0 {
        raw = rawData[len(rawData)-1]
    }

    // Required: false
    // AllowEmptyValue: false

    if raw == "" { // empty values pass all other validations
        return nil
    }

    value, err := swag.ConvertInt32(raw)
    if err != nil {
        return errors.InvalidType("take", "query", "int32", raw)
    }
    o.Take = &value

    return nil
}
