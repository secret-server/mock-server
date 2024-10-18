// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/runtime/security"
	"github.com/go-openapi/strfmt"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"

	"github.com/secret-server/mock-server/auth"
	"github.com/secret-server/mock-server/models"
	"github.com/secret-server/mock-server/restapi/operations"
	"github.com/secret-server/mock-server/restapi/operations/authentication"
	"github.com/secret-server/mock-server/restapi/operations/roles"
	"github.com/secret-server/mock-server/restapi/operations/secrets"
	"github.com/secret-server/mock-server/restapi/operations/users"

	"github.com/go-openapi/swag"
	"github.com/patrickmn/go-cache"
	"gopkg.in/natefinch/lumberjack.v2"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	datastore "github.com/secret-server/mock-datastore/datastore"
)

//go:generate swagger generate server --target ..\..\mock-server --name SecretServerRestAPI --spec ..\swagger.yaml --principal jwt.MapClaims

type BearTokenData struct {
    User datastore.User   `json:"user"`
    ApiAccess bool   `json:"apiaccess"`
    BearToken  string `json:"beartoken"`
    RefresshToken string `json:"refreshtoken"`
}

type BearTokenInterface interface {
	Data() BearTokenData;
}

func (b BearTokenData) Data() BearTokenData {
    return b;
}


var tokenCache *cache.Cache
var tokenCacheTimeout  = 3600;
var tokenCacheExpiration time.Duration;
var secondsTillExpire string;
var accessRoleId int = -1;
	
// var exampleFlags = struct {
// 	Example1 string `long:"example1" description:"Sample for showing how to configure cmd-line flags"`
// 	Example2 string `long:"example2" description:"Further info at https://github.com/jessevdk/go-flags"`
// }{}

var serverFlags = struct {
	FileFolder string `short:"f" long:"FileFolder" description:"Full path to the folder containing mock files"`
	CacheTimeout int `short:"t" long:"TokenTimeout" description:"Timeout of the token cache"`
	RoleAccess string `short:"r" long:"AccessRole" description:"The role used to access the API"`
}{}


const (
	datastorePath = "datastore/"
)

var datastorage datastore.Datastore;

func configureFlags(api *operations.SecretServerRestAPIAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
	// https://github.com/go-swagger/go-swagger/blob/master/examples/tutorials/todo-list/server-complete/restapi/configure_todo_list.go
	// https://github.com/jessevdk/go-flags
	// https://elfsternberg.com/blog/writing-microservice-swagger-part-3-adding-command-line-arguments/
	api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ 
		{
			ShortDescription: "Server Flags",
			LongDescription:  "",
			Options:          &serverFlags,
		},
	}

	if api != nil && api.CommandLineOptionsGroups == nil {
		api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{}
	}

	//zap.ReplaceGlobals(zap.Must(zap.NewProduction()))
	zap.ReplaceGlobals(createLogger())
}

func createLogger() *zap.Logger {
	stdout := zapcore.AddSync(os.Stdout)

	file := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "logs/app.log",
		MaxSize:    10, // megabytes
		MaxBackups: 3,
		MaxAge:     7, // days
	})

	level := zap.NewAtomicLevelAt(zap.InfoLevel)

	productionCfg := zap.NewProductionEncoderConfig()
	productionCfg.TimeKey = "timestamp"
	productionCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	fileEncoder := zapcore.NewJSONEncoder(productionCfg)

	developmentCfg := zap.NewDevelopmentEncoderConfig()
	developmentCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(developmentCfg)

	//zap.ReplaceGlobals(zap.Must(zap.NewProduction()))
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, stdout, level),
		zapcore.NewCore(fileEncoder, file, level),
	)

	return zap.New(core)
}

func configureAPI(api *operations.SecretServerRestAPIAPI) http.Handler {
	defer zap.L().Sync()

	api.Logger = log.Printf
	// api.Logger = zap.S().Debugf

	pwd, err := os.Getwd()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    fmt.Println("Current directory="+pwd)


	//+----------------------------------------------------+
	// configure the api here

	//+----------------------------------------------------+
	// server file configiration
	// default to the input folder flags
	// if not set, then use the environment variable
	// if not set, then use the default datastore path
	if(serverFlags.FileFolder=="") {
		serverFlags.FileFolder = os.Getenv("SECRET_SERVER_FILE_FOLDER");
	}
	// if(serverFlags.FileFolder=="") {
	// 	message := "Missing required environment variable SECRET_SERVER_FILE_FOLDER or command line flag -f";
	// 	err := fmt.Errorf(message);
    //     fmt.Println(err)
    //     os.Exit(1)
	// }
	if(serverFlags.FileFolder=="") {
		serverFlags.FileFolder=datastorePath;
	}

	storage, err := datastore.New(serverFlags.FileFolder);
    if err != nil {
        panic(err)
    }
	datastorage = storage;

	//+----------------------------------------------------+
	// API access - Role access configuration
	// default to the input RoleAccess flag
	// if not set, then use the environment variable
	if(serverFlags.RoleAccess=="") {
		serverFlags.RoleAccess = os.Getenv("SECRET_SERVER_ROLE_ACCESS");
	}
	if(serverFlags.RoleAccess=="") {
		message := "Missing required environment variable SECRET_SERVER_ROLE_ACCESS or command line flag -r";
		err := fmt.Errorf(message);
        fmt.Println(err);
        os.Exit(1)
	}

	//  datastore.Role
	var accessRole, roleErr = datastorage.GetRoleByName(serverFlags.RoleAccess);
	if(roleErr!=nil) {
        fmt.Println(roleErr);
		err := fmt.Errorf("Invalid Role Access value=%s.  Must be a Role in the datastore", serverFlags.RoleAccess);
        fmt.Println(err);
        os.Exit(1)
	}
	accessRoleId = accessRole.ID;

	//+----------------------------------------------------+
	// session token cache
	// default to the input CacheTimeout flag
	// if not set, then use the environment variable
	// if not set, then use the default value
	tokenCacheExpiration = time.Duration(tokenCacheTimeout)*time.Second;
	if(tokenCache==nil) {
		// pull the environment variable, could be set in the docker-compose file or the .env file
		tokenTimeout, exist  := os.LookupEnv("SECRET_SERVER_TOKEN_TIMEOUT");
		if( exist ) {
			n, err := strconv.Atoi(tokenTimeout)
			if err == nil {	
				tokenCacheTimeout = n;
			}
		}

		// always use the command line flag if set
		if( serverFlags.CacheTimeout>0 ) {
			tokenCacheTimeout = serverFlags.CacheTimeout;
		}		

		tokenCacheExpiration := time.Duration(tokenCacheTimeout) * time.Second;
		cleanupInterval := tokenCacheExpiration;
		tokenCache = cache.New(tokenCacheExpiration, cleanupInterval)
		zap.L().Info("Token cache created");
	}
	secondsTillExpire = fmt.Sprintf("%#v", tokenCacheTimeout);
	

	//+----------------------------------------------------+
	// Log the configuration state	
	zap.L().Info("Configuration ", 
		zap.String("FileFolder", serverFlags.FileFolder), 
		zap.String("RequiredAccessRole", serverFlags.RoleAccess), 
		zap.Int("Timeout", tokenCacheTimeout));

	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()
	api.MultipartformConsumer = runtime.DiscardConsumer
	api.UrlformConsumer = runtime.DiscardConsumer

	api.BinProducer = runtime.ByteStreamProducer()
	api.JSONProducer = runtime.JSONProducer()

	// You may change here the memory limit for this multipart form parser. Below is the default (32 MB).
	// authentication.OAuth2ServiceAuthorizeMaxParseMemory = 32 << 20

	api.AuthenticationOAuth2ServiceAuthorizeHandler = authentication.OAuth2ServiceAuthorizeHandlerFunc(
			func(params authentication.OAuth2ServiceAuthorizeParams) middleware.Responder {
		var password = pointerToString(params.Password);
		var logPw = "";
		if( len(password) > 0 ) {
			logPw = "*************";
		}

		var username = pointerToString(params.Username);
		var refreshToken = pointerToString(params.RefreshToken);
		zap.L().Info("Authenticate",
			zap.String("GrantType", params.GrantType),
			zap.String("Username", username),
			zap.String("Password", logPw ),
			zap.String("RefreshToken", refreshToken));
			
		var errorMessage string = "";
		if( params.GrantType=="password" ) {
			user, err := datastorage.GetUser(username);
			if err==nil && user.Password == password {
				zap.L().Info("Login verified");
				resposnesOk, err := buildAuthorizeResponse(user);
				if err==nil {
					return resposnesOk;
				}
			}
			errorMessage = "Invalid authentication.  Verify username and password values.";
		} else if( params.GrantType=="refresh_token" ) {
			if(len(strings.TrimSpace(refreshToken))>0 ) {
				var tokenData, found  = tokenCache.Get(refreshToken); 
				if found  {
					zap.L().Info("Refresh token passed")
					cachedUser := tokenData.(BearTokenData).User;
					resposnesOk, err := buildAuthorizeResponse(cachedUser)
					if err==nil {
						return resposnesOk;
					}
				}
			}
			errorMessage = "Invalid authentication. Missing refresh_token.";
		} else {
			errorMessage = "Invalid authentication.  Missing params or invalid GrantType";
		}

		zap.L().Info(errorMessage, zap.String("GrantType", params.GrantType), zap.String("RefreshToken", refreshToken));

		return returnErrorMessage(errorMessage);
	})

	api.BearerAuthenticator = func(token string, scopedTokenAuthentication security.ScopedTokenAuthentication) runtime.Authenticator {
		fmt.Printf("BearerAuthenticator called with token: %s, scopedTokenAuthentication: %s\r\n", token, spew.Sdump(scopedTokenAuthentication))
		return nil
	}

	// api.BearerAuth = func(token string) (interface{}, error) {
	// 	return nil, errors.NotImplemented("api key auth (Bearer) Authorization from header param [Authorization] has not yet been implemented")
	// }
	//https://stackoverflow.com/questions/52085009/how-to-access-jwt-claims-from-api-handler-functions-in-go-swagger
	api.BearerAuth = func(token string) (*jwt.MapClaims, error) {
        jwtToken := strings.Replace(token, "Bearer ", "", -1)
		claims, err := auth.ParseAndCheckToken(jwtToken);
		if err != nil {
			return nil, err
		}

		bearTokenData, ok := tokenCache.Get(jwtToken);
		if !ok || bearTokenData == nil {
			return nil, err
		}

		access := bearTokenData.(BearTokenInterface).Data().ApiAccess;
		if(access) {
			return (&claims), nil
		}
		return nil, errors.New(403 ," Forbidden. User does not have authorization to access the API");
    }

	api.UsersUsersServiceLookupHandler = users.UsersServiceLookupHandlerFunc(func(params users.UsersServiceLookupParams, principal *jwt.MapClaims) middleware.Responder {
		//fmt.Printf("UsersLookup called with params: %s, and principal: %s\r\n", spew.Sdump(params), spew.Sdump(principal))

		// https://stackoverflow.com/questions/52085009/how-to-access-jwt-claims-from-api-handler-functions-in-go-swagger
		// claims := pointerToClaims(principal)
		// fmt.Println("claims[username]: ", claims["username"]);

		//+ Lookup
		var filter = pointerToString(params.FilterSearchText);
		//fmt.Println("params.FilterSearchText="+filter);

		//+----------------------------------------------------+
		var sortBy0Direction string  = pointerToString(params.SortBy0Direction);
		var sortBy0Priority int32 = pointerToInt32(params.SortBy0Priority);
		sortBy := BuildSortReturn(
			pointerToString(params.SortBy0Name),  sortBy0Direction, sortBy0Priority);
		
		//+----------------------------------------------------+
		// Lookup & build results
		userLookupResults, err := datastorage.UserLookup(filter);
		if err == nil {
			userResults := []*models.UserLookup{};
			for  _, value := range userLookupResults {
				userResults = append(userResults, &models.UserLookup{ID: int32(value.ID), Value: value.Name});
			}

            var userLookupResponse = models.PagingOfUserLookup { 
				BatchCount: int32(1),	
				CurrentPage: int32(1),
				HasNext: false,
				HasPrev: false,
				NextSkip: int32(0),
				PageCount: int32(1),
				PrevSkip: int32(0),
				Records: userResults,
				Severity: models.SeverityNone,
				Skip: int32(0),
				SortBy: sortBy,
				Success: true,
				Take: int32(len(userLookupResults)),
				Total: int32(len(userLookupResults)),
			}	
			
			// Return results
			response := users.NewUsersServiceLookupOK();
			response.SetPayload(&userLookupResponse);
			return response;
		} 

		badResponse := BuildErrorResponse("400", "Invalid request, invalid filter value.", err);
		var badResponseReponse = users.NewUsersServiceLookupBadRequest();
		badResponseReponse.SetPayload(&badResponse);
		return badResponseReponse;	
	})

	if api.AuthenticationOAuth2ServiceAuthorizeHandler == nil {
		api.AuthenticationOAuth2ServiceAuthorizeHandler = authentication.OAuth2ServiceAuthorizeHandlerFunc(func(params authentication.OAuth2ServiceAuthorizeParams) middleware.Responder {
			return middleware.NotImplemented("operation authentication.OAuth2ServiceAuthorize has not yet been implemented")
		})
	}
	if api.RolesRolesServiceCreateHandler == nil {
		api.RolesRolesServiceCreateHandler = roles.RolesServiceCreateHandlerFunc(func(params roles.RolesServiceCreateParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceCreate has not yet been implemented")
		})
	}

	api.RolesRolesServiceGetHandler = roles.RolesServiceGetHandlerFunc(func(params roles.RolesServiceGetParams, principal *jwt.MapClaims) middleware.Responder {
		// fmt.Printf("SecretsServiceGetLookup called with params: %s, and principal: %s\r\n", spew.Sdump(params), spew.Sdump(principal))
		id := params.ID;

		lookupRole, err := datastorage.GetRole(int(id));
		if err == nil {
			// 2024-06-19T14:15:22Z
			// time.Parse
			var date strfmt.DateTime;
			if(len(lookupRole.Created)>0) {
				dateTime, _ := time.Parse("2006-01-02T15:04:05Z", lookupRole.Created);
				date = strfmt.DateTime(dateTime);
			}
			lookupResults := models.RoleModel{
				ID: int32(lookupRole.ID), 
				Name: lookupRole.Name,
				Created: date,
				Enabled: lookupRole.Enabled,
				IsSystem: lookupRole.IsSystem,
			};
			response := roles.NewRolesServiceGetOK();
			response.SetPayload(&lookupResults);
			return response;
		} 

		badResponse := BuildErrorResponse("400", "Invalid request.", err);
		var badResponseReponse = roles.NewRolesServiceGetBadRequest();
		badResponseReponse.SetPayload(&badResponse);
		return badResponseReponse;			
	})

	api.RolesRolesServiceGetAllHandler = roles.RolesServiceGetAllHandlerFunc(func(params roles.RolesServiceGetAllParams, principal *jwt.MapClaims) middleware.Responder {
		var filterUserId = pointerToInt32(params.FilterUserID);
		
		if(filterUserId>0) {
			var idLookup int = int(filterUserId);
			lookupUser, err := datastorage.GetUserById(idLookup);
			if err == nil {
				var sortBy0Direction string  = pointerToString(params.SortBy0Direction);
				var sortBy0Priority int32 = pointerToInt32(params.SortBy0Priority);
				sortBy := BuildSortReturn(
					pointerToString(params.SortBy0Name),  sortBy0Direction, sortBy0Priority);

				roleResults := []*models.RoleModel{};
				for  _, value := range lookupUser.Roles {
					userRole, err := datastorage.GetRole(value);
					if(err==nil) {
						var date strfmt.DateTime;
						if(len(userRole.Created)>0) {
							dateTime, _ := time.Parse("2006-01-02T15:04:05Z", userRole.Created);
							date = strfmt.DateTime(dateTime);
						}
						roleResults = append(roleResults, &models.RoleModel{
							ID: int32(userRole.ID), 
							Name: userRole.Name,
							Created: date,
							Enabled: userRole.Enabled,
							IsSystem: userRole.IsSystem,
						});
					}
				}
				var roleLookupResponse = models.PagingOfRoleModel { 
					BatchCount: int32(1),	
					CurrentPage: int32(1),
					HasNext: false,
					HasPrev: false,
					NextSkip: int32(0),
					PageCount: int32(1),
					PrevSkip: int32(0),
					Records: roleResults,
					Severity: models.SeverityNone,
					Skip: int32(0),
					SortBy: sortBy,
					Success: true,
					Take: int32(len(roleResults)),
					Total: int32(len(roleResults)),
				}	
				
				// Return results
				response := roles.NewRolesServiceGetAllOK();
				response.SetPayload(&roleLookupResponse);
				return response;
			} 
		}
		badResponse := BuildErrorResponse("400", "Invalid request, invalid filter value.", err);
		var badRequestResponse = roles.NewRolesServiceGetAllBadRequest();
		badRequestResponse.SetPayload(&badResponse);
		return badRequestResponse;	
	})

	if api.RolesRolesServiceGetAllRolePermissionsByTypeHandler == nil {
		api.RolesRolesServiceGetAllRolePermissionsByTypeHandler = roles.RolesServiceGetAllRolePermissionsByTypeHandlerFunc(func(params roles.RolesServiceGetAllRolePermissionsByTypeParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceGetAllRolePermissionsByType has not yet been implemented")
		})
	}
	if api.RolesRolesServiceGetRoleGroupsHandler == nil {
		api.RolesRolesServiceGetRoleGroupsHandler = roles.RolesServiceGetRoleGroupsHandlerFunc(func(params roles.RolesServiceGetRoleGroupsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceGetRoleGroups has not yet been implemented")
		})
	}
	if api.RolesRolesServiceGetRolePermissionsHandler == nil {
		api.RolesRolesServiceGetRolePermissionsHandler = roles.RolesServiceGetRolePermissionsHandlerFunc(func(params roles.RolesServiceGetRolePermissionsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceGetRolePermissions has not yet been implemented")
		})
	}
	if api.RolesRolesServicePatchGroupsHandler == nil {
		api.RolesRolesServicePatchGroupsHandler = roles.RolesServicePatchGroupsHandlerFunc(func(params roles.RolesServicePatchGroupsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServicePatchGroups has not yet been implemented")
		})
	}
	if api.RolesRolesServiceStubHandler == nil {
		api.RolesRolesServiceStubHandler = roles.RolesServiceStubHandlerFunc(func(params roles.RolesServiceStubParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceStub has not yet been implemented")
		})
	}
	if api.RolesRolesServiceUpdateHandler == nil {
		api.RolesRolesServiceUpdateHandler = roles.RolesServiceUpdateHandlerFunc(func(params roles.RolesServiceUpdateParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceUpdate has not yet been implemented")
		})
	}
	if api.RolesRolesServiceUpdatePermissionsHandler == nil {
		api.RolesRolesServiceUpdatePermissionsHandler = roles.RolesServiceUpdatePermissionsHandlerFunc(func(params roles.RolesServiceUpdatePermissionsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation roles.RolesServiceUpdatePermissions has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceCreateSecretHandler == nil {
		api.SecretsSecretsServiceCreateSecretHandler = secrets.SecretsServiceCreateSecretHandlerFunc(func(params secrets.SecretsServiceCreateSecretParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceCreateSecret has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceDeleteHandler == nil {
		api.SecretsSecretsServiceDeleteHandler = secrets.SecretsServiceDeleteHandlerFunc(func(params secrets.SecretsServiceDeleteParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceDelete has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceDeleteListFieldListDefinitionsHandler == nil {
		api.SecretsSecretsServiceDeleteListFieldListDefinitionsHandler = secrets.SecretsServiceDeleteListFieldListDefinitionsHandlerFunc(func(params secrets.SecretsServiceDeleteListFieldListDefinitionsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceDeleteListFieldListDefinitions has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceExpireHandler == nil {
		api.SecretsSecretsServiceExpireHandler = secrets.SecretsServiceExpireHandlerFunc(func(params secrets.SecretsServiceExpireParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceExpire has not yet been implemented")
		})
	}

	api.SecretsSecretsServiceGetFieldHandler = secrets.SecretsServiceGetFieldHandlerFunc(func(params secrets.SecretsServiceGetFieldParams, principal *jwt.MapClaims) middleware.Responder {
		// fmt.Printf("SecretsServiceGetLookup called with params: %s, and principal: %s\r\n", spew.Sdump(params), spew.Sdump(principal))
		id := params.ID;
		filter := pointerToString(&params.Slug);

		if(id>0 || len(filter)>0) {
			var idLookup int = int(id);
			lookupSecret, err := datastorage.GetSecretById(idLookup);
			if err == nil {
				var value string = lookupSecret.Slug[filter];
				response := secrets.NewSecretsServiceGetFieldOK();
				response.SetPayload(value);
				return response;
			} 
		}

		badResponse := BuildErrorResponse("400", "Invalid request.", err);
		var badRequestReponse = secrets.NewSecretsServiceGetFieldBadRequest();
		badRequestReponse.SetPayload(&badResponse);
		return badRequestReponse;	
	})


	if api.SecretsSecretsServiceGetGeneralHandler == nil {
		api.SecretsSecretsServiceGetGeneralHandler = secrets.SecretsServiceGetGeneralHandlerFunc(func(params secrets.SecretsServiceGetGeneralParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceGetGeneral has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceGetListFieldHandler == nil {
		api.SecretsSecretsServiceGetListFieldHandler = secrets.SecretsServiceGetListFieldHandlerFunc(func(params secrets.SecretsServiceGetListFieldParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceGetListField has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceGetListFieldListDefinitionsHandler == nil {
		api.SecretsSecretsServiceGetListFieldListDefinitionsHandler = secrets.SecretsServiceGetListFieldListDefinitionsHandlerFunc(func(params secrets.SecretsServiceGetListFieldListDefinitionsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceGetListFieldListDefinitions has not yet been implemented")
		})
	}
	
	api.SecretsSecretsServiceGetLookupHandler = secrets.SecretsServiceGetLookupHandlerFunc(func(params secrets.SecretsServiceGetLookupParams, principal *jwt.MapClaims) middleware.Responder {
		// fmt.Printf("SecretsServiceGetLookup called with params: %s, and principal: %s\r\n", spew.Sdump(params), spew.Sdump(principal))
		id := params.ID;
		filter := pointerToString(params.SecretPath);

		// Lookup & build results
		var lookupSecret datastore.Secret;
		var err error;
		if(id>0) {
			var idLookup int = int(id);
			lookupSecret, err = datastorage.GetSecretById(idLookup);
		} else {
			lookupSecret, err = datastorage.GetSecret(filter);
		}
		if err == nil {
			lookupResults := models.SecretLookup{ID: int32(lookupSecret.ID), Value: lookupSecret.Name};
			response := secrets.NewSecretsServiceGetLookupOK();
			response.SetPayload(&lookupResults);
			return response;
		} 

		badResponse := BuildErrorResponse("400", "Invalid request.", err);
		var badRequestReponse = secrets.NewSecretsServiceGetLookupBadRequest();
		badRequestReponse.SetPayload(&badResponse);
		return badRequestReponse;	
	})

	if api.SecretsSecretsServiceGetRestrictedHandler == nil {
		api.SecretsSecretsServiceGetRestrictedHandler = secrets.SecretsServiceGetRestrictedHandlerFunc(func(params secrets.SecretsServiceGetRestrictedParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceGetRestricted has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceGetSecretExtendedSearchDetailsHandler == nil {
		api.SecretsSecretsServiceGetSecretExtendedSearchDetailsHandler = secrets.SecretsServiceGetSecretExtendedSearchDetailsHandlerFunc(func(params secrets.SecretsServiceGetSecretExtendedSearchDetailsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceGetSecretExtendedSearchDetails has not yet been implemented")
		})
	}

	api.SecretsSecretsServiceGetSecretStateHandler = secrets.SecretsServiceGetSecretStateHandlerFunc(func(params secrets.SecretsServiceGetSecretStateParams, principal *jwt.MapClaims) middleware.Responder {
		// fmt.Printf("SecretsSecretsServiceGetSecretStateHandler called with params: %s, and principal: %s\r\n", spew.Sdump(params), spew.Sdump(principal))
		return middleware.NotImplemented("operation secrets.SecretsServiceGetSecretState has not yet been implemented")
	})

	api.SecretsSecretsServiceGetSecretV2Handler = secrets.SecretsServiceGetSecretV2HandlerFunc(func(params secrets.SecretsServiceGetSecretV2Params, principal *jwt.MapClaims) middleware.Responder {
		// fmt.Printf("SecretsSecretsServiceGetSecretV2Handler called with params: %s, and principal: %s\r\n", spew.Sdump(params), spew.Sdump(principal))
		return middleware.NotImplemented("operation secrets.SecretsServiceGetSecretV2 has not yet been implemented")
	})

	if api.SecretsSecretsServicePutFieldHandler == nil {
		api.SecretsSecretsServicePutFieldHandler = secrets.SecretsServicePutFieldHandlerFunc(func(params secrets.SecretsServicePutFieldParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServicePutField has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceRunHeartBeatHandler == nil {
		api.SecretsSecretsServiceRunHeartBeatHandler = secrets.SecretsServiceRunHeartBeatHandlerFunc(func(params secrets.SecretsServiceRunHeartBeatParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceRunHeartBeat has not yet been implemented")
		})
	}

	api.SecretsSecretsServiceSearchHandler = secrets.SecretsServiceSearchHandlerFunc(func(params secrets.SecretsServiceSearchParams, principal *jwt.MapClaims) middleware.Responder {
		var filter = pointerToString(params.FilterSearchText);

		var sortBy0Direction string  = pointerToString(params.SortBy0Direction);
		var sortBy0Priority int32 = pointerToInt32(params.SortBy0Priority);
		sortBy := BuildSortReturn(
			pointerToString(params.SortBy0Name),  sortBy0Direction, sortBy0Priority);
		
		filteredSecrets, err := datastorage.SecretLookup(filter);
		if err == nil {
			lookupResults := []*models.SecretSummary{};
			for  _, value := range filteredSecrets {
				lookupResults = append(lookupResults, &models.SecretSummary{ID: int32(value.ID), Name: value.Name});
			}

            var lookupResponse = models.PagingOfSecretSummary { 
				BatchCount: int32(1),	
				CurrentPage: int32(1),
				HasNext: false,
				HasPrev: false,
				NextSkip: int32(0),
				PageCount: int32(1),
				PrevSkip: int32(0),
				Records: lookupResults,
				Severity: models.SeverityNone,
				Skip: int32(0),
				SortBy: sortBy,
				Success: true,
				Take: int32(len(lookupResults)),
				Total: int32(len(lookupResults)),
			}		

			response := secrets.NewSecretsServiceSearchOK()
			response.SetPayload(&lookupResponse);
			return response;
		}
		badResponse := BuildErrorResponse("400", "Invalid request, invalid filter value.", err);

		var badResponseRequest = secrets.NewSecretsServiceSearchBadRequest();
		badResponseRequest.SetPayload(&badResponse);
		return badResponseRequest;	
	})

	api.SecretsSecretsServiceSearchSecretLookupHandler = secrets.SecretsServiceSearchSecretLookupHandlerFunc(func(params secrets.SecretsServiceSearchSecretLookupParams, principal *jwt.MapClaims) middleware.Responder {
		var filter = pointerToString(params.FilterSearchText);

		var sortBy0Direction string  = pointerToString(params.SortBy0Direction);
		var sortBy0Priority int32 = pointerToInt32(params.SortBy0Priority);
		sortBy := BuildSortReturn(
			pointerToString(params.SortBy0Name),  sortBy0Direction, sortBy0Priority);
		
		filteredSecrets, err := datastorage.SecretLookup(filter);
		if err == nil {
			lookupResults := []*models.SecretLookup{};
			for  _, value := range filteredSecrets {
				lookupResults = append(lookupResults, &models.SecretLookup{ID: int32(value.ID), Value: value.Name});
			}

            var lookupResponse = models.PagingOfSecretLookup { 
				BatchCount: int32(1),	
				CurrentPage: int32(1),
				HasNext: false,
				HasPrev: false,
				NextSkip: int32(0),
				PageCount: int32(1),
				PrevSkip: int32(0),
				Records: lookupResults,
				Severity: models.SeverityNone,
				Skip: int32(0),
				SortBy: sortBy,
				Success: true,
				Take: int32(len(lookupResults)),
				Total: int32(len(lookupResults)),
			}		

			response := secrets.NewSecretsServiceSearchSecretLookupOK()
			response.SetPayload(&lookupResponse);
			return response;
		}
		badResponse := BuildErrorResponse("400", "Invalid request, invalid filter value.", err);

		var badResponseRequest = secrets.NewSecretsServiceSearchSecretLookupBadRequest();
		badResponseRequest.SetPayload(&badResponse);
		return badResponseRequest;	
	})

	api.SecretsSecretsServiceSearchV2Handler = secrets.SecretsServiceSearchV2HandlerFunc(func(params secrets.SecretsServiceSearchV2Params, principal *jwt.MapClaims) middleware.Responder {
		var filter = pointerToString(params.FilterSearchText);

		var sortBy0Direction string  = pointerToString(params.SortBy0Direction);
		var sortBy0Priority int32 = pointerToInt32(params.SortBy0Priority);
		sortBy := BuildSortReturn(
			pointerToString(params.SortBy0Name),  sortBy0Direction, sortBy0Priority);
		
		filteredSecrets, err := datastorage.SecretLookup(filter);
		if err == nil {
			lookupResults := []*models.SecretSummary{};
			for  _, value := range filteredSecrets {
				lookupResults = append(lookupResults, &models.SecretSummary{ID: int32(value.ID), Name: value.Name});
			}

            var lookupResponse = models.PagingOfSecretSummary { 
				BatchCount: int32(1),	
				CurrentPage: int32(1),
				HasNext: false,
				HasPrev: false,
				NextSkip: int32(0),
				PageCount: int32(1),
				PrevSkip: int32(0),
				Records: lookupResults,
				Severity: models.SeverityNone,
				Skip: int32(0),
				SortBy: sortBy,
				Success: true,
				Take: int32(len(lookupResults)),
				Total: int32(len(lookupResults)),
			}		

			response := secrets.NewSecretsServiceSearchOK()
			response.SetPayload(&lookupResponse);
			return response;
		}
		badResponse := BuildErrorResponse("400", "Invalid request, invalid filter value.", err);

		var badResponseRequest = secrets.NewSecretsServiceSearchBadRequest();
		badResponseRequest.SetPayload(&badResponse);
		return badResponseRequest;	
	})
	
	if api.SecretsSecretsServiceUndeleteSecretHandler == nil {
		api.SecretsSecretsServiceUndeleteSecretHandler = secrets.SecretsServiceUndeleteSecretHandlerFunc(func(params secrets.SecretsServiceUndeleteSecretParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceUndeleteSecret has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceUndeleteSecretV2Handler == nil {
		api.SecretsSecretsServiceUndeleteSecretV2Handler = secrets.SecretsServiceUndeleteSecretV2HandlerFunc(func(params secrets.SecretsServiceUndeleteSecretV2Params, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceUndeleteSecretV2 has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceUpdateExpirationHandler == nil {
		api.SecretsSecretsServiceUpdateExpirationHandler = secrets.SecretsServiceUpdateExpirationHandlerFunc(func(params secrets.SecretsServiceUpdateExpirationParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceUpdateExpiration has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceUpdateListFieldListDefinitionsHandler == nil {
		api.SecretsSecretsServiceUpdateListFieldListDefinitionsHandler = secrets.SecretsServiceUpdateListFieldListDefinitionsHandlerFunc(func(params secrets.SecretsServiceUpdateListFieldListDefinitionsParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceUpdateListFieldListDefinitions has not yet been implemented")
		})
	}
	if api.SecretsSecretsServiceUpdateSecretHandler == nil {
		api.SecretsSecretsServiceUpdateSecretHandler = secrets.SecretsServiceUpdateSecretHandlerFunc(func(params secrets.SecretsServiceUpdateSecretParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation secrets.SecretsServiceUpdateSecret has not yet been implemented")
		})
	}
	if api.UsersUsersServiceCreateUserRolesHandler == nil {
		api.UsersUsersServiceCreateUserRolesHandler = users.UsersServiceCreateUserRolesHandlerFunc(func(params users.UsersServiceCreateUserRolesParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation users.UsersServiceCreateUserRoles has not yet been implemented")
		})
	}

	api.UsersUsersServiceGetHandler = users.UsersServiceGetHandlerFunc(func(params users.UsersServiceGetParams, principal *jwt.MapClaims) middleware.Responder {
		id := params.ID;
		if(id>0) {
			var idLookup int = int(id);
			lookupUser, err := datastorage.GetUserById(idLookup);
			if err == nil {
				lookupResults := models.UserModel{
					UserName: lookupUser.Name,
					DisplayName: lookupUser.DisplayName,
					EmailAddress: lookupUser.Email,
					ID: int32(idLookup),
				};
				response := users.NewUsersServiceGetOK();
				response.SetPayload(&lookupResults);
				return response;
			} 
		}
		badResponse := BuildErrorResponse("400", "Invalid request.", err);
		var badRequestResponse = users.NewUsersServiceGetBadRequest();
		badRequestResponse.SetPayload(&badResponse);
		return badRequestResponse;	
	})

	api.UsersUsersServiceGetRolesHandler = users.UsersServiceGetRolesHandlerFunc(func(params users.UsersServiceGetRolesParams, principal *jwt.MapClaims) middleware.Responder {
		id := params.ID;
		if(id>0) {
			var idLookup int = int(id);
			lookupUser, err := datastorage.GetUserById(idLookup);
			if err == nil {
				var sortBy0Direction string  = pointerToString(params.SortBy0Direction);
				var sortBy0Priority int32 = pointerToInt32(params.SortBy0Priority);
				sortBy := BuildSortReturn(
					pointerToString(params.SortBy0Name),  sortBy0Direction, sortBy0Priority);

				roleSummary := []*models.RoleSummary{};
				for  _, value := range lookupUser.Roles {
					userRole, err := datastorage.GetRole(value);
					if(err==nil) {
						roleSummary = append(roleSummary, &models.RoleSummary{Name: userRole.Name, RoleID: int32(value)});
					}
				}
	
				var userRoleResponse = models.PagingOfRoleSummary { 
					BatchCount: int32(1),	
					CurrentPage: int32(1),
					HasNext: false,
					HasPrev: false,
					NextSkip: int32(0),
					PageCount: int32(1),
					PrevSkip: int32(0),
					Records: roleSummary,
					Severity: models.SeverityNone,
					Skip: int32(0),
					SortBy: sortBy,
					Success: true,
					Take: int32(len(roleSummary)),
					Total: int32(len(roleSummary)),
				}	
				
				response := users.NewUsersServiceGetRolesOK();
				response.SetPayload(&userRoleResponse);
				return response;
			} 
		}
		badResponse := BuildErrorResponse("400", "Invalid request.", err);
		var badRequestResponse = users.NewUsersServiceGetRolesBadRequest();
		badRequestResponse.SetPayload(&badResponse);
		return badRequestResponse;	
	})

	if api.UsersUsersServiceGetUserRolesHandler == nil {
		api.UsersUsersServiceGetUserRolesHandler = users.UsersServiceGetUserRolesHandlerFunc(func(params users.UsersServiceGetUserRolesParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation users.UsersServiceGetUserRoles has not yet been implemented")
		})
	}
	if api.UsersUsersServiceLookupHandler == nil {
		api.UsersUsersServiceLookupHandler = users.UsersServiceLookupHandlerFunc(func(params users.UsersServiceLookupParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation users.UsersServiceLookup has not yet been implemented")
		})
	}
	if api.UsersUsersServicePatchUserHandler == nil {
		api.UsersUsersServicePatchUserHandler = users.UsersServicePatchUserHandlerFunc(func(params users.UsersServicePatchUserParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation users.UsersServicePatchUser has not yet been implemented")
		})
	}
	if api.UsersUsersServiceUpdateUserHandler == nil {
		api.UsersUsersServiceUpdateUserHandler = users.UsersServiceUpdateUserHandlerFunc(func(params users.UsersServiceUpdateUserParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation users.UsersServiceUpdateUser has not yet been implemented")
		})
	}
	if api.UsersUsersServiceUpdateUserRolesHandler == nil {
		api.UsersUsersServiceUpdateUserRolesHandler = users.UsersServiceUpdateUserRolesHandlerFunc(func(params users.UsersServiceUpdateUserRolesParams, principal *jwt.MapClaims) middleware.Responder {
			return middleware.NotImplemented("operation users.UsersServiceUpdateUserRoles has not yet been implemented")
		})
	}

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

func BuildSortReturn(sortBy0Name string, sortBy0Direction  string, sortBy0Priority int32) ([]*models.Sort) {
	sortBy := []*models.Sort{};
	if sortBy0Direction != "" && sortBy0Name != "" {
		// var paramSortDirection models.SortDirection = sortBy0Direction;
		var direction models.SortDirection;
		if string(*models.SortDirectionAsc.Pointer()) == sortBy0Direction {
			direction = models.SortDirectionAsc;
		} else if string(*models.SortDirectionDesc.Pointer()) == sortBy0Direction {
			direction = models.SortDirectionDesc;
		} else {
			direction = models.SortDirectionNone;
		}
		sortBy = append(sortBy, &models.Sort{
				Direction: models.NewSortDirection(direction), Name: &sortBy0Name, Priority: sortBy0Priority });	
	}
	return sortBy;
}


func returnErrorMessage(errorMessage string) *authentication.OAuth2ServiceAuthorizeBadRequest {
	var tokenErrorResponse = models.TokenErrorResponse { Message:  &errorMessage }
	var authenticationBadRequest =  authentication.NewOAuth2ServiceAuthorizeBadRequest();
	authenticationBadRequest.SetPayload(&tokenErrorResponse);
	return authenticationBadRequest;
}

func returnAuthenticationFailedResponse() *users.UsersServiceLookupForbidden {
	var message string = "Unauthorized access to API endpoint"
	var authenticationFailedResponse = models.AuthenticationFailedResponse { Message:  &message }
	var forbiddenAccessResponse = users.NewUsersServiceLookupForbidden()
	forbiddenAccessResponse.SetPayload(&authenticationFailedResponse);
	return forbiddenAccessResponse;
}


func buildAuthorizeResponse(user datastore.User) (*authentication.OAuth2ServiceAuthorizeOK, error) {
	fmt.Printf("buildAuthorizeResponse called with user: %s\r\n", spew.Sdump(user))

	bearerToken, err := auth.CreateToken(user.Name);
	fmt.Printf("buildAuthorizeResponse bearerToken: %s, err: %s\r\n", bearerToken, spew.Sdump(err))
	if( err!=nil ) {
		return nil, err;
	}
	
	refreshToken := fmt.Sprintf("refresh.%s", uuid.NewString());

	tokenType := "bearer";
	var tokenResponse = models.TokenResponse { 
		AccessToken:  &bearerToken,
		ExpiresIn:  &secondsTillExpire,
		RefreshToken:  refreshToken,
		TokenType:  &tokenType,
	}
	
	access := datastorage.DoesUserHaveRoleName(user, serverFlags.RoleAccess);

	// var expire time.Duration = time.Duration(30) * time.Second;
	data := BearTokenData{User: user, ApiAccess: access, BearToken: bearerToken, RefresshToken: refreshToken}
	var bear BearTokenInterface = data;

	tokenCache.Set(bearerToken, bear, tokenCacheExpiration);
	tokenCache.Set(refreshToken, bear, tokenCacheExpiration);

	var authentication =  authentication.NewOAuth2ServiceAuthorizeOK();
	authentication.SetPayload(&tokenResponse);
	return authentication, nil;
}


func BuildErrorResponse(errorCode string, errorMessage string, err error) models.BadRequestResponse {
	var errorDetails string = err.Error();
	var badResponse = models.BadRequestResponse {  ErrorCode: "400", Message:  &errorMessage, MessageDetail: errorDetails }
	return badResponse
}


func pointerToClaims(claims *jwt.MapClaims) jwt.MapClaims {
	if( claims==nil ) {
		return nil;
	}
	return *claims;
}

func pointerToString(value *string) string {
	if( value==nil ) {
		return "";
	}
	return *value;
}

func pointerToInt32(value *int32) int32 {
	if( value==nil ) {
		return 0
	}
	return *value;
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
