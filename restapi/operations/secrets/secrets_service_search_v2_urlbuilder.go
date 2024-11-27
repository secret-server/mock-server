// Code generated by go-swagger; DO NOT EDIT.

package secrets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
    "errors"
    "net/url"
    golangswaggerpaths "path"

    "github.com/go-openapi/swag"
)

// SecretsServiceSearchV2URL generates an URL for the secrets service search v2 operation
type SecretsServiceSearchV2URL struct {
    FilterAllowDoubleLocks            *bool
    FilterDoNotCalculateTotal         *bool
    FilterDoubleLockID                *int32
    FilterExtFieldsCombined           *string
    FilterExtendedFields              []string
    FilterExtendedTypeID              *int32
    FilterFolderID                    *int32
    FilterHasLauncher                 *bool
    FilterHeartbeatStatus             *string
    FilterIncludeActive               *bool
    FilterIncludeInactive             *bool
    FilterIncludeRestricted           *bool
    FilterIncludeSubFolders           *bool
    FilterIsExactMatch                *bool
    FilterOnlyCheckedOutSecrets       *bool
    FilterOnlyRPCEnabled              *bool
    FilterOnlySecretsCheckedOutByUser *bool
    FilterOnlySharedWithMe            *bool
    FilterPasswordTypeIds             []int64
    FilterPermissionRequired          *string
    FilterScope                       *string
    FilterSearchField                 *string
    FilterSearchFieldSlug             *string
    FilterSearchText                  *string
    FilterSecretIds                   []int64
    FilterSecretTemplateIds           []int64
    FilterSecretTemplateIdsCombined   *string
    FilterSiteID                      *int32
    Skip                              *int32
    SortBy0Direction                  *string
    SortBy0Name                       *string
    SortBy0Priority                   *int32
    Take                              *int32

    _basePath string
    // avoid unkeyed usage
    _ struct{}
}

// WithBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SecretsServiceSearchV2URL) WithBasePath(bp string) *SecretsServiceSearchV2URL {
    o.SetBasePath(bp)
    return o
}

// SetBasePath sets the base path for this url builder, only required when it's different from the
// base path specified in the swagger spec.
// When the value of the base path is an empty string
func (o *SecretsServiceSearchV2URL) SetBasePath(bp string) {
    o._basePath = bp
}

// Build a url path and query string
func (o *SecretsServiceSearchV2URL) Build() (*url.URL, error) {
    var _result url.URL

    var _path = "/api/v2/secrets"

    _basePath := o._basePath
    if _basePath == "" {
        _basePath = "/SecretServer"
    }
    _result.Path = golangswaggerpaths.Join(_basePath, _path)

    qs := make(url.Values)

    var filterAllowDoubleLocksQ string
    if o.FilterAllowDoubleLocks != nil {
        filterAllowDoubleLocksQ = swag.FormatBool(*o.FilterAllowDoubleLocks)
    }
    if filterAllowDoubleLocksQ != "" {
        qs.Set("filter.allowDoubleLocks", filterAllowDoubleLocksQ)
    }

    var filterDoNotCalculateTotalQ string
    if o.FilterDoNotCalculateTotal != nil {
        filterDoNotCalculateTotalQ = swag.FormatBool(*o.FilterDoNotCalculateTotal)
    }
    if filterDoNotCalculateTotalQ != "" {
        qs.Set("filter.doNotCalculateTotal", filterDoNotCalculateTotalQ)
    }

    var filterDoubleLockIDQ string
    if o.FilterDoubleLockID != nil {
        filterDoubleLockIDQ = swag.FormatInt32(*o.FilterDoubleLockID)
    }
    if filterDoubleLockIDQ != "" {
        qs.Set("filter.doubleLockId", filterDoubleLockIDQ)
    }

    var filterExtFieldsCombinedQ string
    if o.FilterExtFieldsCombined != nil {
        filterExtFieldsCombinedQ = *o.FilterExtFieldsCombined
    }
    if filterExtFieldsCombinedQ != "" {
        qs.Set("filter.extFieldsCombined", filterExtFieldsCombinedQ)
    }

    var filterExtendedFieldsIR []string
    for _, filterExtendedFieldsI := range o.FilterExtendedFields {
        filterExtendedFieldsIS := filterExtendedFieldsI
        if filterExtendedFieldsIS != "" {
            filterExtendedFieldsIR = append(filterExtendedFieldsIR, filterExtendedFieldsIS)
        }
    }

    filterExtendedFields := swag.JoinByFormat(filterExtendedFieldsIR, "multi")

    for _, qsv := range filterExtendedFields {
        qs.Add("filter.extendedFields", qsv)
    }

    var filterExtendedTypeIDQ string
    if o.FilterExtendedTypeID != nil {
        filterExtendedTypeIDQ = swag.FormatInt32(*o.FilterExtendedTypeID)
    }
    if filterExtendedTypeIDQ != "" {
        qs.Set("filter.extendedTypeId", filterExtendedTypeIDQ)
    }

    var filterFolderIDQ string
    if o.FilterFolderID != nil {
        filterFolderIDQ = swag.FormatInt32(*o.FilterFolderID)
    }
    if filterFolderIDQ != "" {
        qs.Set("filter.folderId", filterFolderIDQ)
    }

    var filterHasLauncherQ string
    if o.FilterHasLauncher != nil {
        filterHasLauncherQ = swag.FormatBool(*o.FilterHasLauncher)
    }
    if filterHasLauncherQ != "" {
        qs.Set("filter.hasLauncher", filterHasLauncherQ)
    }

    var filterHeartbeatStatusQ string
    if o.FilterHeartbeatStatus != nil {
        filterHeartbeatStatusQ = *o.FilterHeartbeatStatus
    }
    if filterHeartbeatStatusQ != "" {
        qs.Set("filter.heartbeatStatus", filterHeartbeatStatusQ)
    }

    var filterIncludeActiveQ string
    if o.FilterIncludeActive != nil {
        filterIncludeActiveQ = swag.FormatBool(*o.FilterIncludeActive)
    }
    if filterIncludeActiveQ != "" {
        qs.Set("filter.includeActive", filterIncludeActiveQ)
    }

    var filterIncludeInactiveQ string
    if o.FilterIncludeInactive != nil {
        filterIncludeInactiveQ = swag.FormatBool(*o.FilterIncludeInactive)
    }
    if filterIncludeInactiveQ != "" {
        qs.Set("filter.includeInactive", filterIncludeInactiveQ)
    }

    var filterIncludeRestrictedQ string
    if o.FilterIncludeRestricted != nil {
        filterIncludeRestrictedQ = swag.FormatBool(*o.FilterIncludeRestricted)
    }
    if filterIncludeRestrictedQ != "" {
        qs.Set("filter.includeRestricted", filterIncludeRestrictedQ)
    }

    var filterIncludeSubFoldersQ string
    if o.FilterIncludeSubFolders != nil {
        filterIncludeSubFoldersQ = swag.FormatBool(*o.FilterIncludeSubFolders)
    }
    if filterIncludeSubFoldersQ != "" {
        qs.Set("filter.includeSubFolders", filterIncludeSubFoldersQ)
    }

    var filterIsExactMatchQ string
    if o.FilterIsExactMatch != nil {
        filterIsExactMatchQ = swag.FormatBool(*o.FilterIsExactMatch)
    }
    if filterIsExactMatchQ != "" {
        qs.Set("filter.isExactMatch", filterIsExactMatchQ)
    }

    var filterOnlyCheckedOutSecretsQ string
    if o.FilterOnlyCheckedOutSecrets != nil {
        filterOnlyCheckedOutSecretsQ = swag.FormatBool(*o.FilterOnlyCheckedOutSecrets)
    }
    if filterOnlyCheckedOutSecretsQ != "" {
        qs.Set("filter.onlyCheckedOutSecrets", filterOnlyCheckedOutSecretsQ)
    }

    var filterOnlyRPCEnabledQ string
    if o.FilterOnlyRPCEnabled != nil {
        filterOnlyRPCEnabledQ = swag.FormatBool(*o.FilterOnlyRPCEnabled)
    }
    if filterOnlyRPCEnabledQ != "" {
        qs.Set("filter.onlyRPCEnabled", filterOnlyRPCEnabledQ)
    }

    var filterOnlySecretsCheckedOutByUserQ string
    if o.FilterOnlySecretsCheckedOutByUser != nil {
        filterOnlySecretsCheckedOutByUserQ = swag.FormatBool(*o.FilterOnlySecretsCheckedOutByUser)
    }
    if filterOnlySecretsCheckedOutByUserQ != "" {
        qs.Set("filter.onlySecretsCheckedOutByUser", filterOnlySecretsCheckedOutByUserQ)
    }

    var filterOnlySharedWithMeQ string
    if o.FilterOnlySharedWithMe != nil {
        filterOnlySharedWithMeQ = swag.FormatBool(*o.FilterOnlySharedWithMe)
    }
    if filterOnlySharedWithMeQ != "" {
        qs.Set("filter.onlySharedWithMe", filterOnlySharedWithMeQ)
    }

    var filterPasswordTypeIdsIR []string
    for _, filterPasswordTypeIdsI := range o.FilterPasswordTypeIds {
        filterPasswordTypeIdsIS := swag.FormatInt64(filterPasswordTypeIdsI)
        if filterPasswordTypeIdsIS != "" {
            filterPasswordTypeIdsIR = append(filterPasswordTypeIdsIR, filterPasswordTypeIdsIS)
        }
    }

    filterPasswordTypeIds := swag.JoinByFormat(filterPasswordTypeIdsIR, "multi")

    for _, qsv := range filterPasswordTypeIds {
        qs.Add("filter.passwordTypeIds", qsv)
    }

    var filterPermissionRequiredQ string
    if o.FilterPermissionRequired != nil {
        filterPermissionRequiredQ = *o.FilterPermissionRequired
    }
    if filterPermissionRequiredQ != "" {
        qs.Set("filter.permissionRequired", filterPermissionRequiredQ)
    }

    var filterScopeQ string
    if o.FilterScope != nil {
        filterScopeQ = *o.FilterScope
    }
    if filterScopeQ != "" {
        qs.Set("filter.scope", filterScopeQ)
    }

    var filterSearchFieldQ string
    if o.FilterSearchField != nil {
        filterSearchFieldQ = *o.FilterSearchField
    }
    if filterSearchFieldQ != "" {
        qs.Set("filter.searchField", filterSearchFieldQ)
    }

    var filterSearchFieldSlugQ string
    if o.FilterSearchFieldSlug != nil {
        filterSearchFieldSlugQ = *o.FilterSearchFieldSlug
    }
    if filterSearchFieldSlugQ != "" {
        qs.Set("filter.searchFieldSlug", filterSearchFieldSlugQ)
    }

    var filterSearchTextQ string
    if o.FilterSearchText != nil {
        filterSearchTextQ = *o.FilterSearchText
    }
    if filterSearchTextQ != "" {
        qs.Set("filter.searchText", filterSearchTextQ)
    }

    var filterSecretIdsIR []string
    for _, filterSecretIdsI := range o.FilterSecretIds {
        filterSecretIdsIS := swag.FormatInt64(filterSecretIdsI)
        if filterSecretIdsIS != "" {
            filterSecretIdsIR = append(filterSecretIdsIR, filterSecretIdsIS)
        }
    }

    filterSecretIds := swag.JoinByFormat(filterSecretIdsIR, "multi")

    for _, qsv := range filterSecretIds {
        qs.Add("filter.secretIds", qsv)
    }

    var filterSecretTemplateIdsIR []string
    for _, filterSecretTemplateIdsI := range o.FilterSecretTemplateIds {
        filterSecretTemplateIdsIS := swag.FormatInt64(filterSecretTemplateIdsI)
        if filterSecretTemplateIdsIS != "" {
            filterSecretTemplateIdsIR = append(filterSecretTemplateIdsIR, filterSecretTemplateIdsIS)
        }
    }

    filterSecretTemplateIds := swag.JoinByFormat(filterSecretTemplateIdsIR, "multi")

    for _, qsv := range filterSecretTemplateIds {
        qs.Add("filter.secretTemplateIds", qsv)
    }

    var filterSecretTemplateIdsCombinedQ string
    if o.FilterSecretTemplateIdsCombined != nil {
        filterSecretTemplateIdsCombinedQ = *o.FilterSecretTemplateIdsCombined
    }
    if filterSecretTemplateIdsCombinedQ != "" {
        qs.Set("filter.secretTemplateIdsCombined", filterSecretTemplateIdsCombinedQ)
    }

    var filterSiteIDQ string
    if o.FilterSiteID != nil {
        filterSiteIDQ = swag.FormatInt32(*o.FilterSiteID)
    }
    if filterSiteIDQ != "" {
        qs.Set("filter.siteId", filterSiteIDQ)
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
func (o *SecretsServiceSearchV2URL) Must(u *url.URL, err error) *url.URL {
    if err != nil {
        panic(err)
    }
    if u == nil {
        panic("url can't be nil")
    }
    return u
}

// String returns the string representation of the path with query string
func (o *SecretsServiceSearchV2URL) String() string {
    return o.Must(o.Build()).String()
}

// BuildFull builds a full url with scheme, host, path and query string
func (o *SecretsServiceSearchV2URL) BuildFull(scheme, host string) (*url.URL, error) {
    if scheme == "" {
        return nil, errors.New("scheme is required for a full url on SecretsServiceSearchV2URL")
    }
    if host == "" {
        return nil, errors.New("host is required for a full url on SecretsServiceSearchV2URL")
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
func (o *SecretsServiceSearchV2URL) StringFull(scheme, host string) string {
    return o.Must(o.BuildFull(scheme, host)).String()
}
