package service

import (
	"net/http"
	"strconv"
	//log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
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

//NewRouter creates and configures a mux router
func NewRouter() *mux.Router {
	schemas = &client.Schemas{}

	// ApiVersion
	apiVersion := schemas.AddType("apiVersion", client.Resource{})
	apiVersion.CollectionMethods = []string{}

	// Schema
	schemas.AddType("schema", client.Schema{})

	// Error
	err := schemas.AddType("error", model.AuthServiceError{})
	err.CollectionMethods = []string{}

	// Identity
	identity := schemas.AddType("identity", client.Identity{})
	identity.CollectionMethods = []string{"GET"}
	identity.ResourceMethods = []string{"GET"}
	identity.PluralName = "identities"

	// API framework routes
	router := mux.NewRouter().StrictSlash(true)

	router.Methods("GET").Path("/").Handler(api.VersionsHandler(schemas, "v1-rancher-auth"))
	router.Methods("GET").Path("/v1-rancher-auth/schemas").Handler(api.SchemasHandler(schemas))
	router.Methods("GET").Path("/v1-rancher-auth/schemas/{id}").Handler(api.SchemaHandler(schemas))
	router.Methods("GET").Path("/v1-rancher-auth").Handler(api.VersionHandler(schemas, "v1-rancher-auth"))

	// Application routes
	router.Methods("POST").Path("/v1-rancher-auth/token").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetToken)))
	router.Methods("GET").Path("/v1-rancher-auth/me/identities").Handler(api.ApiHandler(schemas, http.HandlerFunc(GetIdentities)))
	router.Methods("GET").Path("/v1-rancher-auth/identities").Handler(api.ApiHandler(schemas, http.HandlerFunc(SearchIdentities)))
	//router.Methods("POST").Path("/v1-rancher-auth/reload").Handler(api.ApiHandler(schemas, authenticate(GetDNSRecords)))

	return router
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
