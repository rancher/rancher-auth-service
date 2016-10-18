package service

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/server"
)

const (
	samlParam        = "samlJWT"
	redirectBackBase = "redirectBackBase"
	redirectBackPath = "redirectBackPath"
	getSamlAuthToken = "/v1-auth/saml/authtoken"
)

//CreateToken is a handler for route /token and returns the jwt token after authenticating the user
func CreateToken(w http.ResponseWriter, r *http.Request) {
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("GetToken failed with error: %v", err)
	}
	var jsonInput map[string]string

	err = json.Unmarshal(bytes, &jsonInput)
	if err != nil {
		log.Errorf("unmarshal failed with error: %v", err)
	}

	securityCode := jsonInput["code"]
	accessToken := jsonInput["accessToken"]

	if securityCode != "" {
		log.Debugf("CreateToken called with securityCode %s", securityCode)
		//getToken
		token, err := server.CreateToken(jsonInput)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error getting the token: %v", err))
			return
		}
		api.GetApiContext(r).Write(&token)
	} else if accessToken != "" {
		log.Debugf("RefreshToken called with accessToken %s", accessToken)
		//getToken
		token, err := server.RefreshToken(jsonInput)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			ReturnHTTPError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error getting the token: %v", err))
			return
		}
		api.GetApiContext(r).Write(&token)
	} else {
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
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
			return
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
			return
		}
	} else {
		log.Debug("No Authorization header found")
		ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		return
	}
}

//SearchIdentities is a handler for route /identities and filters (id + type or name) and returns the search results using the passed filters
func SearchIdentities(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")

	if authHeader != "" {
		// header value format will be "Bearer <token>"
		if !strings.HasPrefix(authHeader, "Bearer") {
			log.Debugf("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer")
		accessToken = strings.TrimSpace(accessToken)
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
				return
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
				return
			}
		} else {
			ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
			return
		}
	} else {
		log.Debug("No Authorization header found")
		ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
		return
	}
}

//UpdateConfig is a handler for POST /config, loads the provider with the config and saves the config back to Cattle database
func UpdateConfig(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("UpdateConfig failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}
	var authConfig model.AuthConfig

	err = json.Unmarshal(bytes, &authConfig)
	if err != nil {
		log.Errorf("UpdateConfig unmarshal failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}

	if authConfig.Provider == "" {
		log.Errorf("UpdateConfig: Provider is a required field")
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content, Provider is a required field")
		return
	}

	err = server.UpdateConfig(authConfig)
	if err != nil {
		log.Errorf("UpdateConfig failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}
	log.Debugf("Updated config, listing the config back")
	if authConfig.Provider == "shibbolethconfig" {
		//enable the saml SP wrapper over the saml routes
		addRouteHandler(server.SamlServiceProvider.RequireAccount(http.HandlerFunc(HandleSamlPost)), "SamlLogin")
		addRouteHandler(server.SamlServiceProvider, "SamlACS")
		addRouteHandler(server.SamlServiceProvider, "SamlMetadata")
	}

	//list the config and return in response
	config, err := server.GetConfig("", true)
	if err == nil {
		apiContext.Write(&config)
	} else {
		//failed to get the config
		log.Debugf("GetConfig failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to list the config")
		return
	}
}

//GetConfig is a handler for GET /config, lists the provider config
func GetConfig(w http.ResponseWriter, r *http.Request) {
	apiContext := api.GetApiContext(r)
	authHeader := r.Header.Get("Authorization")
	var accessToken string
	// header value format will be "Bearer <token>"
	if authHeader != "" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Errorf("GetMyIdentities Failed to find Bearer token %v", authHeader)
			ReturnHTTPError(w, r, http.StatusUnauthorized, "Unauthorized, please provide a valid token")
			return
		}
		accessToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	config, err := server.GetConfig(accessToken, true)
	if err == nil {
		apiContext.Write(&config)
	} else {
		//failed to get the config
		log.Debugf("GetConfig failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to get the auth config")
		return
	}
}

//Reload is a handler for POST /reloadconfig, reloads the config from Cattle database and initializes the provider
func Reload(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Reload called")
	err := server.Reload()
	if err != nil {
		//failed to reload the config from DB
		log.Debugf("Reload failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to reload the auth config")
		return
	}
}

//HandleSamlPost handles the SAML Post
func HandleSamlPost(w http.ResponseWriter, r *http.Request) {
	//get all X-Saml- headers and pass it to the provider
	log.Debugf("HandleSamlPost: request url is %v", r.URL.String())
	cookie, _ := r.Cookie("token")
	log.Infof("token cookie: %v", cookie)

	samlData := make(map[string][]string)

	for key, val := range r.Header {
		if strings.HasPrefix(key, "X-Saml-") {
			samlData[strings.ToLower(strings.TrimPrefix(key, "X-Saml-"))] = val
		}
	}
	log.Debugf("HandleSamlPost: Received a SAML POST data %v", samlData)

	//get the SAML data, create a jwt token and Redirect to ${redirectBackBase (or if not provided, api.host)}/v1-auth/saml/authtoken with query param json = map
	mapB, err := json.Marshal(samlData)
	if err != nil {
		//failed to get the saml data
		log.Debugf("HandleSamlPost failed to unmarshal saml data with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to unmarshal the saml data")
		return
	}
	log.Debugf("HandleSamlPost saml %v ", string(mapB))

	var redirectBackBaseParam string
	if r.URL.Query() != nil {
		redirectBackBaseParam = r.URL.Query().Get(redirectBackBase)
		if redirectBackBaseParam == "" {
			redirectBackBaseParam = server.GetRancherAPIHost()
		}
	} else {
		redirectBackBaseParam = server.GetRancherAPIHost()
	}
	redirectURL := redirectBackBaseParam + getSamlAuthToken
	v := r.URL.Query()
	v.Add(samlParam, string(cookie.Value))
	queryStr := v.Encode()

	redirectURL = redirectURL + "?" + queryStr

	log.Debugf("redirecting the user to %v", redirectURL)

	tokenCookie := &http.Cookie{
		Name:    "token",
		Value:   "",
		Secure:  false,
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Date(1982, time.February, 10, 23, 0, 0, 0, time.UTC),
	}
	http.SetCookie(w, tokenCookie)

	http.Redirect(w, r, redirectURL, http.StatusFound)

}

//GetSamlAuthToken handles the SAML login using query parameters and creates an auth token calling cattle
func GetSamlAuthToken(w http.ResponseWriter, r *http.Request) {
	log.Debugf("GetSamlAuthToken : url is %v", r.URL.String())

	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		//failed to get the url query parameters
		log.Errorf("GetSamlAuthToken failed to parse query params with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to get the auth query parameters")
		return
	}

	redirectURL := server.GetSamlRedirectURL(query.Get(redirectBackBase), query.Get(redirectBackPath))

	samlJWT := query.Get(samlParam)
	ok, samlData := server.IsSamlJWTValid(samlJWT)

	if !ok {
		//failed to validate the SAML JWT
		log.Errorf("GetSamlAuthToken failed to validate the SAML JWT")
		redirectURL = addErrorToRedirect(redirectURL, "401")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	log.Debugf("Received SAML  data %v", samlData)
	jwt, errToken := server.GetSamlAuthToken(samlData)

	if errToken != nil {
		//failed to get token from cattle
		log.Errorf("GetSamlAuthToken failed to Get token from cattle with error %v", errToken.Error())
		if strings.Contains(errToken.Error(), "401") {
			//add error=401 query param to redirect
			redirectURL = addErrorToRedirect(redirectURL, "401")
		} else {
			redirectURL = addErrorToRedirect(redirectURL, "500")
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	tokenCookie := &http.Cookie{
		Name:   "token",
		Value:  jwt,
		Secure: false,
		Path:   "/",
	}
	http.SetCookie(w, tokenCookie)

	log.Debugf("redirecting the user with token to %v", redirectURL)

	http.Redirect(w, r, redirectURL, http.StatusFound)

}

func addErrorToRedirect(redirectURL string, code string) string {
	//add code query param to redirect
	redirectURLInst, err := url.Parse(redirectURL)
	if err == nil {
		v := redirectURLInst.Query()
		v.Add("errCode", code)
		redirectURLInst.RawQuery = v.Encode()
		redirectURL = redirectURLInst.String()
	} else {
		log.Errorf("Error parsing the URL %v  ,error is: %v", redirectURL, err)
		redirectURL = redirectURL + "?errCode=" + code
	}
	return redirectURL
}

//GetRedirectURL gets the redirect URL
func GetRedirectURL(w http.ResponseWriter, r *http.Request) {
	redirectResponse, err := server.GetRedirectURL()
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(redirectResponse)
	} else {
		//failed to get the redirectURL
		log.Debugf("GetRedirectUrl failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to get the redirect URL")
		return
	}
}

//DoSamlLogout redirects to Saml Logout
func DoSamlLogout(w http.ResponseWriter, r *http.Request) {
	if server.SamlServiceProvider != nil {
		if server.SamlServiceProvider.ServiceProvider.IDPMetadata != nil {
			entityID := server.SamlServiceProvider.ServiceProvider.IDPMetadata.EntityID
			entityURL, _ := url.Parse(entityID)
			redirectURL := entityURL.Scheme + "://" + entityURL.Host + "/idp/profile/Logout"
			log.Debugf("redirecting the user to %v", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		log.Info("No Logout URL - Saml/Shibboleth IDPMetadata not found")
	} else {
		log.Info("No Logout URL - Saml/Shibboleth provider is not configured")
	}
}
