package service

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/server"
	"io/ioutil"
	"net/http"
	"strings"
)

//GetToken is a handler for route /token and returns the jwt token after authenticating the user
func GetToken(w http.ResponseWriter, r *http.Request) {
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("GetToken failed with error: %v", err)
	}
	var t map[string]string

	err = json.Unmarshal(bytes, &t)
	if err != nil {
		log.Errorf("unmarshal failed with error: %v", err)
	}
	log.Infof("map %v", t)

	securityCode := t["code"]
	accessToken := t["accessToken"]

	log.Infof("securityCode %s", securityCode)
	log.Infof("acessToken %s", accessToken)

	if securityCode != "" {
		//getToken
		token, err := server.GetToken(securityCode)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error getting the token: %v", err))
		} else {
			json.NewEncoder(w).Encode(token)
		}
	} else if accessToken != "" {
		//getToken
		token, err := server.RefreshToken(accessToken)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error getting the token: %v", err))
		} else {
			json.NewEncoder(w).Encode(token)
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
			log.Debug("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		log.Debugf("token is this  %s", accessToken)

		identities, err := server.GetIdentities(accessToken)
		log.Debugf("identities  %v", identities)
		if err == nil {
			resp := client.IdentityCollection{}
			resp.Data = identities

			apiContext.Write(&resp)
		} else {
			//failed to get the user identities
			log.Debug("GetIdentities Failed with error %v", err)
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
			log.Debug("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		log.Debugf("token is this  %s", accessToken)

		//see which filters are passed, if none then error 400

		externalId := r.URL.Query().Get("externalId")
		externalIdType := r.URL.Query().Get("externalIdType")
		name := r.URL.Query().Get("name")

		if externalId != "" && externalIdType != "" {
			//search by id and type
			identity, err := server.GetIdentity(externalId, externalIdType, accessToken)
			if err == nil {
				apiContext.Write(&identity)
			} else {
				//failed to search the identities
				log.Errorf("SearchIdentities Failed with error %v", err)
				ReturnHTTPError(w, r, http.StatusInternalServerError, "Internal Server Error")
			}
		} else if name != "" {

			identities, err := server.SearchIdentities(name, true, accessToken)
			log.Debugf("identities  %v", identities)
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
