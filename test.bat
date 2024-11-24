REM https://everything.curl.dev/usingcurl/verbose/writeout.html

echo off

:: DONE
:: ["GET"]["/api/v1/users/lookup"] = users.NewUsersServiceLookup(o.context, o.UsersUsersServiceLookupHandler)
:: TODO: Fix the lookup to allow '&' multiple filters.  Add test.
curl http://127.0.0.1:8080/SecretServer/api/v1/users/lookup?filter.searchText=jason -H "Authorization: Bearer %1" -H "accept: application/json"

:: DONE
::["GET"]["/api/v1/users/{id}"] = users.NewUsersServiceGet(o.context, o.UsersUsersServiceGetHandler)
:: Required:
::    User ID: ID
echo:
curl http://127.0.0.1:8080/SecretServer/api/v1/users/1 -H "Authorization: Bearer %1" -H "accept: application/json"

:: DONE
:: ["GET"]["/api/v1/users/{id}/roles"] = users.NewUsersServiceGetRoles(o.context, o.UsersUsersServiceGetRolesHandler)
echo:
echo ["GET"]["/api/v1/users/{id}/roles"]
curl http://127.0.0.1:8080/SecretServer/api/v1/users/1/roles -H "Authorization: Bearer %1" -H "accept: application/json"

:: DONE
:: ["GET"]["/api/v1/secrets/lookup"] = secrets.NewSecretsServiceSearchSecretLookup(o.context, o.SecretsSecretsServiceSearchSecretLookupHandler)
echo:
echo ["GET"]["/api/v1/secrets/lookup"]
curl http://127.0.0.1:8080/SecretServer/api/v1/secrets/lookup?filter.searchText=caDatabase -H "Authorization: Bearer %1" -H "accept: application/json"

:: DONE
:: ["GET"]["/api/v1/secrets/lookup/{id}"] = secrets.NewSecretsServiceGetLookup(o.context, o.SecretsSecretsServiceGetLookupHandler)
echo:
echo ["GET"]["/api/v1/secrets/lookup/{id}"]
curl http://127.0.0.1:8080/SecretServer/api/v1/secrets/lookup/50 -H "Authorization: Bearer %1" -H "accept: application/json"

:: DONE
:: ["GET"]["/api/v1/secrets"] = secrets.NewSecretsServiceSearch(o.context, o.SecretsSecretsServiceSearchHandler)
echo:
echo ["GET"]["/api/v1/secrets"]
curl http://127.0.0.1:8080/SecretServer/api/v1/secrets?filter.searchText=caDatabase -H "Authorization: Bearer %1" -H "accept: application/json"


:: TODO
:: ["GET"]["/api/v2/secrets"] = secrets.NewSecretsServiceSearchV2(o.context, o.SecretsSecretsServiceSearchV2Handler)
:: echo:
:: curl http://127.0.0.1:8080/SecretServer/api/v2/secrets?filter.searchText=caDatabase -H "Authorization: Bearer %1" -H "accept: application/json"
echo:
echo ["GET"]["/api/v2/secrets"]
curl http://127.0.0.1:8080/SecretServer/api/v2/secrets?filter.searchText=caDatabase -H "Authorization: Bearer %1" -H "accept: application/json"

:: TODO
:: ["GET"]["/api/v2/secrets"] = secrets.NewSecretsServiceSearchV2(o.context, o.SecretsSecretsServiceSearchV2Handler)
:: echo:
:: curl http://127.0.0.1:8080/SecretServer/api/v2/secrets/0?secretPath=caDatabase -H "Authorization: Bearer %1" -H "accept: application/json"


:: DONE
::["GET"]["/api/v1/secrets/{id}/fields/{slug}"] = secrets.NewSecretsServiceGetField(o.context, o.SecretsSecretsServiceGetFieldHandler)
:: Required
::    Secret ID: ID
::    Secret field name: Slug
::    Example: ID=50, Slug=server, result=192.168.10.131
echo:
echo ["GET"]["/api/v1/secrets/{id}/fields/{slug}"]
curl http://127.0.0.1:8080/SecretServer/api/v1/secrets/50/fields/server -H "Authorization: Bearer %1" -H "accept: application/json"


:: TODO: Not sure how this is used
:: ["GET"]["/api/v1/secrets/{id}/fields/{slug}/listdetails"] = secrets.NewSecretsServiceGetListFieldListDefinitions(o.context, o.SecretsSecretsServiceGetListFieldListDefinitionsHandler)
:: Required
::    Secret ID: ID
::    Secret field name: Slug
::    Example: ID=50, Slug=server, result=192.168.10.131
:: echo:
:: curl http://127.0.0.1:8080/SecretServer/api/v1/secrets/50/fields/server/listdetails -H "Authorization: Bearer %1" -H "accept: application/json"

:: TODO
:: ["GET"]["/api/v1/roles/{id}"] = roles.NewRolesServiceGet(o.context, o.RolesRolesServiceGetHandler)
echo:
echo ["GET"]["/api/v1/roles/{id}"]
curl http://127.0.0.1:8080/SecretServer/api/v1/roles/1 -H "Authorization: Bearer %1" -H "accept: application/json"


:: TODO
:: ["GET"]["/api/v1/roles"] = roles.NewRolesServiceGetAll(o.context, o.RolesRolesServiceGetAllHandler)
echo:
echo ["GET"]["/api/v1/roles"]
curl http://127.0.0.1:8080/SecretServer/api/v1/roles?filter.userId=1 -H "Authorization: Bearer %1" -H "accept: application/json"



echo:
