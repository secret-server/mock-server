#!/bin/bash

#####################################################
# Sample input
# localhost:3000
# kevin.kelche@example.com
# bleach.out.34

CYAN=$'\e[0;96m';
GREEN=$'\e[0;92m'
MAGENTA=$'\e[0;95m';
RED=$'\e[0;91m'
YELLOW=$'\e[0;93m';
NO_COLOR=$'\e[0m'

#####################################################
# Intro
echo -e "${GREEN}"
echo -e "Test the Secret Server API"

#####################################################
# Collect and verify input
echo -e "* Input required: Secret Server address:port"
# verify input
echo -e "\nEnter the Secret Server address:port of the Rest API service${YELLOW}"
read secretServiceUrl
if [[ -z $secretServiceUrl ]] ;
then
  echo "${CYAN}>>> Error: Missing Secret Server address:port. Ending test${NO_COLOR}"
  exit 1
fi

echo -e "${GREEN}"
echo -e "Enter the username & password to access Rest API"
read -p "${GREEN}Username:${YELLOW} " uservar
read -sp "${GREEN}Password:${YELLOW} " passvar
if [[ -z $uservar ]] ;
then
  echo "${CYAN}>>> Error: Missing username. Ending verification${NO_COLOR}"
  exit 1
fi

if [[ -z $passvar ]] ;
then
  echo "${CYAN}>>> Error: Missing password. Ending verification${NO_COLOR}"
  exit 1
fi


#####################################################
curlCmd=http://$secretServiceUrl/SecretServer/oauth2/token 
echo -e ""
echo -e "${GREEN}"
echo -e "$curlCmd${NO_COLOR}"
accessToken=$(curl -s -g -k POST $curlCmd -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=password&username=$uservar&password=$passvar" | jq -r '.access_token' )
echo -e "accessToken: $accessToken"


# ["GET"]["/api/v1/users/lookup"]
echo -e "${GREEN}"
echo -e "/api/v1/users/lookup"
echo -e "/api/v1/users/lookup?filter.searchText=jason${NO_COLOR}"
echo -e "TODO: Fix the lookup to allow '&' multiple filters.  Add test."
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/users/lookup?filter.searchText=jason
userJasonLookup=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "User Jason lookup: $userJasonLookup"


# ["GET"]["/api/v1/users/{id}"]
echo -e "${GREEN}"
echo -e "/api/v1/users/{id}"
echo -e "/api/v1/users/1${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/users/1
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/users/{id}/roles"]
echo -e "${GREEN}"
echo -e "/api/v1/users/{id}/roles"
echo -e "/api/v1/users/1/roles${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/users/1/roles
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/secrets/lookup"]
echo -e "${GREEN}"
echo -e "/api/v1/secrets/lookup"
echo -e "/api/v1/secrets/lookup?filter.searchText=caDatabase${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/secrets/lookup?filter.searchText=caDatabase
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/secrets/lookup/{id}"]
echo -e "${GREEN}"
echo -e "/api/v1/secrets/lookup"
echo -e "/api/v1/secrets/lookup/50${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/secrets/lookup/50
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/secrets"]
echo -e "${GREEN}"
echo -e "/api/v1/secrets"
echo -e "/api/v1/secrets?filter.searchText=caDatabase${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/secrets?filter.searchText=caDatabase
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v2/secrets"]
echo -e "${GREEN}"
echo -e "/api/v2/secrets"
echo -e "/api/v2/secrets?filter.searchText=caDatabase${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v2/secrets?filter.searchText=caDatabase
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v2/secrets"]
echo -e "${GREEN}"
echo -e "/api/v2/secrets"
echo -e "/api/v2/secrets/0?secretPath=caDatabase${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v2/secrets/0?secretPath=caDatabase
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/secrets/{id}/fields/{slug}"]
echo -e "${GREEN}"
echo -e "Secret ID: ID"
echo -e "Secret field name: Slug"
echo -e "Example: ID=50, Slug=server, result=192.168.10.131"
echo -e "/api/v1/secrets/{id}/fields/{slug}"
echo -e "/api/v1/secrets/50/fields/server${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/secrets/50/fields/server
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/secrets/{id}/fields/{slug}/listdetails"]
echo -e "${GREEN}"
echo -e "Secret ID: ID"
echo -e "Secret field name: Slug"
echo -e "Example: ID=50, Slug=server, result=192.168.10.131"
echo -e "/api/v1/secrets/{id}/fields/{slug}/listdetails"
echo -e "/api/v1/secrets/50/fields/server/listdetails${NO_COLOR}"
eurlCmd=http://$secretServiceUrl/SecretServer/api/v1/secrets/50/fields/server/listdetails
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/roles/{id}"]
echo -e "${GREEN}"
echo -e "/api/v1/roles/{id}"
echo -e "/api/v1/roles/1${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/roles/1
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"


# ["GET"]["/api/v1/roles"]
echo -e "${GREEN}"
echo "/api/v1/roles"
echo -e "api/v1/roles?filter.userId=1${NO_COLOR}"
curlCmd=http://$secretServiceUrl/SecretServer/api/v1/roles?filter.userId=1
result=$(curl -s -g -k POST $curlCmd -H "Authorization: Bearer $accessToken" -H "accept: application/json")
echo -e "$result"

echo -e "${NO_COLOR}"
exit 1

