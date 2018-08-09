package service

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	v2client "github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers"
)

//Route defines the properties of a go mux http route
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

//Routes array of Route defined
type Routes []Route

var schemas *client.Schemas

var router *mux.Router

//NewRouter creates and configures a mux router
func NewRouter() *mux.Router {
	schemas = getSchemas()

	// API framework routes
	router = mux.NewRouter().StrictSlash(true)

	router.Methods("GET").Path("/").Handler(api.VersionsHandler(schemas, "v1-auth"))
	router.Methods("GET").Path("/v1-auth/schemas").Handler(api.SchemasHandler(schemas))
	router.Methods("GET").Path("/v1-auth/schemas/{id}").Handler(api.SchemaHandler(schemas))
	router.Methods("GET").Path("/v1-auth").Handler(api.VersionHandler(schemas, "v1-auth"))

	// Application routes
	router.Methods("POST").Path("/v1-auth/config").Handler(api.ApiHandler(schemas, http.HandlerFunc(UpdateConfig)))
	router.Methods("GET").Path("/v1-auth/config").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetConfig)))
	router.Methods("GET").Path("/v1-auth/configs").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetConfig)))
	router.Methods("POST").Path("/v1-auth/reload").Handler(api.ApiHandler(schemas, http.HandlerFunc(Reload)))
	router.Methods("POST").Path("/v1-auth/token").Handler(api.ApiHandler(schemas, http.HandlerFunc(CreateToken)))
	router.Methods("GET").Path("/v1-auth/me/identities").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetIdentities)))
	router.Methods("GET").Path("/v1-auth/identities").Handler(api.ApiHandler(schemas, http.HandlerFunc(SearchIdentities)))
	router.Methods("GET").Path("/v1-auth/redirectUrl").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetRedirectURL)))
	router.Methods("GET").Path("/v1-auth/saml/logout").Handler(api.ApiHandler(schemas, http.HandlerFunc(DoSamlLogout)))

	router.Methods("GET").Path("/v1-auth/saml/login").Handler(api.ApiHandler(schemas, http.HandlerFunc(HandleSamlLogin)))
	router.Methods("POST").Path("/v1-auth/saml/acs").Handler(api.ApiHandler(schemas, http.HandlerFunc(ServeHTTP)))
	router.Methods("GET").Path("/v1-auth/saml/metadata").Handler(api.ApiHandler(schemas, http.HandlerFunc(ServeHTTP)))

	router.Methods("POST").Path("/v1-auth/testlogin").Handler(api.ApiHandler(schemas, http.HandlerFunc(TestLogin)))

	return router
}

func getSchemas() *client.Schemas {
	schemas = &client.Schemas{}
	// ApiVersion
	apiVersion := schemas.AddType("apiVersion", client.Resource{})
	apiVersion.CollectionMethods = []string{}

	// Schema
	schemas.AddType("schema", client.Schema{})

	// Identity
	identity := schemas.AddType("identity", v2client.Identity{})
	identity.CollectionMethods = []string{"GET"}
	identity.ResourceMethods = []string{"GET"}
	identity.PluralName = "identities"

	// AuthConfig
	authconfig := schemas.AddType("config", model.AuthConfig{})
	authconfig.CollectionMethods = []string{"GET", "POST"}
	authconfig.ResourceMethods = []string{"GET", "POST"}
	authconfig.PluralName = "configs"

	// TestAuthConfig
	testAuthconfig := schemas.AddType("testAuthConfig", model.TestAuthConfig{})
	testAuthconfig.CollectionMethods = []string{"POST"}
	a := testAuthconfig.ResourceFields["authConfig"]
	a.Type = "authConfig"
	testAuthconfig.ResourceFields["authConfig"] = a
	testAuthconfig.PluralName = "testAuthConfigs"

	//Token
	token := schemas.AddType("token", model.Token{})
	token.CollectionMethods = []string{}

	// Error
	err := schemas.AddType("error", model.AuthServiceError{})
	err.CollectionMethods = []string{}

	// For providers
	for _, value := range providers.Providers {
		p, err := providers.GetProvider(value)
		if err != nil {
			continue
		}
		providerConfig := schemas.AddType(value, p.GetProviderConfigResource())
		providerConfig.CollectionMethods = []string{}
		providerConfig = p.CustomizeSchema(providerConfig)
	}

	return schemas
}

//ReturnHTTPError handles sending out CatalogError response
func ReturnHTTPError(w http.ResponseWriter, r *http.Request, httpStatus int, errorMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	err := model.AuthServiceError{
		Resource: client.Resource{
			Type: "error",
		},
		Status:  strconv.Itoa(httpStatus),
		Message: errorMessage,
	}

	api.CreateApiContext(w, r, schemas)
	api.GetApiContext(r).Write(&err)
}
