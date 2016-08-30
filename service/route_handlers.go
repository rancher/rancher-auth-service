package service

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/server"
	"io/ioutil"
	"net/http"
	"strings"
)

//CreateToken is a handler for route /token and returns the jwt token after authenticating the user
func CreateToken(w http.ResponseWriter, r *http.Request) {
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("GetToken failed with error: %v", err)
	}
	var t map[string]string

	err = json.Unmarshal(bytes, &t)
	if err != nil {
		log.Errorf("unmarshal failed with error: %v", err)
	}

	securityCode := t["code"]
	accessToken := t["accessToken"]

	if securityCode != "" {
		log.Debugf("CreateToken called with securityCode %s", securityCode)
		//getToken
		token, err := server.CreateToken(securityCode)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error getting the token: %v", err))
		} else {
			api.GetApiContext(r).Write(&token)
		}
	} else if accessToken != "" {
		log.Debugf("RefreshToken called with accessToken %s", accessToken)
		//getToken
		token, err := server.RefreshToken(accessToken)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error getting the token: %v", err))
		} else {
			api.GetApiContext(r).Write(&token)
		}
	} else {
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
	}
}

//GetIdentities is a handler for route /me/identities and returns group memberships and details of the user
func GetIdentities(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// header value format will be "Bearer <token>"
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debugf("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		identities, err := server.GetIdentities(accessToken)

		if err == nil {
			resp := client.IdentityCollection{}
			resp.Data = identities

			apiContext.Write(&resp)
		} else {
			//failed to get the user identities
			log.Debugf("GetIdentities Failed with error %v", err)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, failed to get identities")
		}
	} else {
		log.Debug("No Authorization header found")
		ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
	}
}

//SearchIdentities is a handler for route /identities and filters (id + type or name) and returns the search results using the passed filters
func SearchIdentities(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// header value format will be "Bearer <token>"
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debugf("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		//see which filters are passed, if none then error 400
		externalID := r.URL.Query().Get("externalId")
		externalIDType := r.URL.Query().Get("externalIdType")
		name := r.URL.Query().Get("name")

		if externalID != "" && externalIDType != "" {
			log.Debugf("SearchIdentities by externalID: %v and externalIDType: %v", externalID, externalIDType)
			//search by id and type
			identity, err := server.GetIdentity(externalID, externalIDType, accessToken)
			if err == nil {
				log.Debugf("Found identity  %v", identity)
				apiContext.Write(&identity)
			} else {
				//failed to search the identities
				log.Errorf("SearchIdentities Failed with error %v", err)
				ReturnHTTPError(w, r, http.StatusInternalServerError, "Internal Server Error")
			}
		} else if name != "" {
			log.Debugf("SearchIdentities by name: %v", name)
			identities, err := server.SearchIdentities(name, true, accessToken)
			log.Debugf("Found identities  %v", identities)
			if err == nil {
				resp := client.IdentityCollection{}
				resp.Data = identities

				apiContext.Write(&resp)
			} else {
				//failed to search the identities
				log.Errorf("SearchIdentities Failed with error %v", err)
				ReturnHTTPError(w, r, http.StatusInternalServerError, "Internal Server Error")
			}
		} else {
			ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		}
	} else {
		log.Debug("No Authorization header found")
		ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
	}
}

//UpdateConfig is a handler for POST /config, loads the provider with the config and saves the config back to Cattle database
func UpdateConfig(w http.ResponseWriter, r *http.Request) {
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("UpdateConfig failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
	}
	var authConfig model.AuthConfig

	err = json.Unmarshal(bytes, &authConfig)
	if err != nil {
		log.Errorf("UpdateConfig unmarshal failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
	}

	if authConfig.Provider == "" {
		log.Errorf("UpdateConfig: Provider is a required field")
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content, Provider is a required field")
	}
	err = server.UpdateConfig(authConfig)
	if err != nil {
		log.Errorf("UpdateConfig failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
	} else {
		log.Debugf("Updated config, listing the config back")
		//list the config and return in response
		config, err := server.GetConfig("")
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
		} else {
			//failed to get the config
			log.Debugf("GetConfig failed with error %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to list the config")
		}
	}
}

//GetConfig is a handler for GET /config, lists the provider config
func GetConfig(w http.ResponseWriter, r *http.Request) {
	//apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")
	var accessToken string
	// header value format will be "Bearer <token>"
	if authHeader != "" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Errorf("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		}
		accessToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	config, err := server.GetConfig(accessToken)
	if err == nil {
		//apiContext.Write(&config) -> apicontext cannot include nested structures
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	} else {
		//failed to get the config
		log.Debugf("GetConfig failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to get the auth config")
	}
}

//Reload is a handler for POST /reloadconfig, reloads the config from Cattle database and initializes the provider
func Reload(w http.ResponseWriter, r *http.Request) {
	err := server.Reload()
	if err != nil {
		//failed to reload the config from DB
		log.Debugf("Reload failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to reload the auth config")
	}
}
