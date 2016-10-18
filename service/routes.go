package service

import (
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/server"
	"net/http"
	"strconv"
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
	schemas = &client.Schemas{}

	// ApiVersion
	apiVersion := schemas.AddType("apiVersion", client.Resource{})
	apiVersion.CollectionMethods = []string{}

	// Schema
	schemas.AddType("schema", client.Schema{})

	// Identity
	identity := schemas.AddType("identity", client.Identity{})
	identity.CollectionMethods = []string{"GET"}
	identity.ResourceMethods = []string{"GET"}
	identity.PluralName = "identities"

	// GithubConfig
	githubconfig := schemas.AddType("githubconfig", model.GithubConfig{})
	githubconfig.CollectionMethods = []string{}

	// ShibbolethConfig
	shibbolethconfig := schemas.AddType("shibbolethconfig", model.ShibbolethConfig{})
	shibbolethconfig.CollectionMethods = []string{}

	// AuthConfig
	authconfig := schemas.AddType("config", model.AuthConfig{})
	authconfig.CollectionMethods = []string{"GET", "POST"}
	authconfig.ResourceMethods = []string{"GET", "POST"}
	authconfig.PluralName = "configs"

	//Token
	token := schemas.AddType("token", model.Token{})
	token.CollectionMethods = []string{}

	// Error
	err := schemas.AddType("error", model.AuthServiceError{})
	err.CollectionMethods = []string{}

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
	router.Methods("GET").Path("/v1-auth/saml/authtoken").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetSamlAuthToken)))
	router.Methods("GET").Path("/v1-auth/saml/logout").Handler(api.ApiHandler(schemas, http.HandlerFunc(DoSamlLogout)))

	router.Methods("GET").Path("/v1-auth/saml/login").Name("SamlLogin")
	router.Methods("POST").Path("/v1-auth/saml/acs").Name("SamlACS")
	router.Methods("GET").Path("/v1-auth/saml/metadata").Name("SamlMetadata")

	if server.SamlServiceProvider != nil {
		log.Debugf("Adding saml routes to router")
		addRouteHandler(server.SamlServiceProvider.RequireAccount(http.HandlerFunc(HandleSamlPost)), "SamlLogin")
		addRouteHandler(server.SamlServiceProvider, "SamlACS")
		addRouteHandler(server.SamlServiceProvider, "SamlMetadata")
	}

	return router
}

func addRouteHandler(handler http.Handler, name string) {
	router.Get(name).Handler(handler)
}

//ReturnHTTPError handles sending out CatalogError response
func ReturnHTTPError(w http.ResponseWriter, r *http.Request, httpStatus int, errorMessage string) {
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
