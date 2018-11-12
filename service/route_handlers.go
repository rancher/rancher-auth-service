package service

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml"
	"github.com/dgrijalva/jwt-go"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/server"
)

const (
	redirectBackBase  = "redirectBackBase"
	redirectBackPath  = "redirectBackPath"
	postSamlTokenHTML = "/v1-auth/saml/tokenhtml"
	tpl               = `
<!DOCTYPE html>
<html>
  <head>
    <script>
      window.onload = function() {
        document.getElementById('TokenHTMLResponseForm').submit();
      }
    </script>
  </head>
  <body>
    <form method="post" action="{{.URL}}" id="TokenHTMLResponseForm">
      <input type="hidden" name="token" value="{{.Token}}" />
      <input type="hidden" name="finalRedirectURL" value="{{.FinalRedirectURL}}" />
      <input type="hidden" name="secure" value="{{.Secure}}" />
    </form>
  </body>
</html>`
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
		log.Debugf("CreateToken called with securityCode")
		//getToken
		token, status, err := server.CreateToken(jsonInput)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			if status == 0 {
				status = http.StatusInternalServerError
			}
			ReturnHTTPError(w, r, status, fmt.Sprintf("%v", err))
			return
		}
		api.GetApiContext(r).Write(&token)
	} else if accessToken != "" {
		log.Debugf("RefreshToken called with accessToken %s", accessToken)
		//getToken
		token, status, err := server.RefreshToken(jsonInput)
		if err != nil {
			log.Errorf("GetToken failed with error: %v", err)
			if status == 0 {
				status = http.StatusInternalServerError
			}
			ReturnHTTPError(w, r, status, fmt.Sprintf("%v", err))
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
			//Must call ldap SearchIdentities with exactMatch=true
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
	_, err := server.Reload(false)
	if err != nil {
		//failed to reload the config from DB
		log.Debugf("Reload failed with error %v", err)
		ReturnHTTPError(w, r, http.StatusInternalServerError, "Failed to reload the auth config")
		return
	}
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

// TestLogin is a test API to check login with code before saving settings to db
func TestLogin(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	cookies := r.Cookies()
	var token string
	for _, c := range cookies {
		if c.Name == "token" {
			token = c.Value
		}
	}

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

	bytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("TestLogin failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}
	var testAuthConfig model.TestAuthConfig

	err = json.Unmarshal(bytes, &testAuthConfig)
	if err != nil {
		log.Errorf("TestLogin unmarshal failed with error: %v", err)
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad Request, Please check the request content")
		return
	}

	if testAuthConfig.AuthConfig.Provider == "" {
		log.Errorf("UpdateConfig: Provider is a required field")
		ReturnHTTPError(w, r, http.StatusBadRequest, "Bad request, Provider is a required field")
		return
	}

	status, err := server.TestLogin(testAuthConfig, accessToken, token)
	if err != nil {
		log.Errorf("TestLogin GetProvider failed with error: %v", err)
		if status == 0 {
			status = http.StatusInternalServerError
		}
		ReturnHTTPError(w, r, status, fmt.Sprintf("%v", err))
	}
}

// HandleSamlLogin is the endpoint for /saml/login endpoint
func HandleSamlLogin(w http.ResponseWriter, r *http.Request) {
	var redirectBackBaseValue string
	s := server.SamlServiceProvider

	s.XForwardedProto = r.Header.Get("X-Forwarded-Proto")

	if r.URL.Query() != nil {
		redirectBackBaseValue = r.URL.Query().Get(redirectBackBase)
		if redirectBackBaseValue == "" {
			redirectBackBaseValue = server.GetRancherAPIHost()
		}
	} else {
		redirectBackBaseValue = server.GetRancherAPIHost()
	}

	if !isWhitelisted(redirectBackBaseValue, s.RedirectWhitelist) {
		log.Errorf("Cannot redirect to anything other than whitelisted domains and rancher api host")
		redirectBackPathValue := r.URL.Query().Get(redirectBackPath)
		redirectURL := server.GetSamlRedirectURL(server.GetRancherAPIHost(), redirectBackPathValue)
		redirectURL = addErrorToRedirect(redirectURL, "422")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	serviceProvider := s.ServiceProvider
	if r.URL.Path == serviceProvider.AcsURL.Path {
		return
	}

	binding := saml.HTTPRedirectBinding
	bindingLocation := serviceProvider.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = saml.HTTPPostBinding
		bindingLocation = serviceProvider.GetSSOBindingLocation(binding)
	}

	req, err := serviceProvider.MakeAuthenticationRequest(bindingLocation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// relayState is limited to 80 bytes but also must be integrety protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a cookie that corresponds to the state
	relayState := base64.URLEncoding.EncodeToString(randomBytes(42))

	secretBlock := x509.MarshalPKCS1PrivateKey(serviceProvider.Key)
	state := jwt.New(jwt.SigningMethodHS256)
	claims := state.Claims.(jwt.MapClaims)
	claims["id"] = req.ID
	claims["uri"] = r.URL.String()
	signedState, err := state.SignedString(secretBlock)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.ClientState.SetState(w, r, relayState, signedState)

	if binding == saml.HTTPRedirectBinding {
		redirectURL := req.Redirect(relayState)
		w.Header().Add("Location", redirectURL.String())
		w.WriteHeader(http.StatusFound)
		return
	}
	if binding == saml.HTTPPostBinding {
		w.Header().Add("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		w.Header().Add("Content-type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><body>`))
		w.Write(req.Post(relayState))
		w.Write([]byte(`</body></html>`))
		return
	}
}

// ServeHTTP is the handler for /saml/metadata and /saml/acs endpoints
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serviceProvider := server.SamlServiceProvider.ServiceProvider
	if r.URL.Path == serviceProvider.MetadataURL.Path {
		buf, _ := xml.MarshalIndent(serviceProvider.Metadata(), "", "  ")
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Write(buf)
		return
	}

	if r.URL.Path == serviceProvider.AcsURL.Path {
		r.ParseForm()
		reqIDs, redirectBackBaseValue, redirectBackPathValue, err := getRequestIDAndRedirectParams(r, server.SamlServiceProvider)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		assertion, err := serviceProvider.ParseResponse(r, reqIDs)
		if err != nil {
			if parseErr, ok := err.(*saml.InvalidResponseError); ok {
				log.Errorf("RESPONSE: ===\n%s\n===\nNOW: %s\nERROR: %s",
					parseErr.Response, parseErr.Now, parseErr.PrivateErr)
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		HandleSamlAssertion(w, r, assertion, server.SamlServiceProvider, redirectBackBaseValue, redirectBackPathValue)
		return
	}

	http.NotFoundHandler().ServeHTTP(w, r)
}

func getRequestIDAndRedirectParams(r *http.Request, s *model.RancherSamlServiceProvider) (reqIDs []string, redirectBackBaseValue string,
	redirectBackPathValue string, err error) {
	for name, value := range s.ClientState.GetStates(r) {
		if strings.HasPrefix(name, "Rancher_") {
			continue
		}
		jwtParser := jwt.Parser{
			ValidMethods: []string{jwt.SigningMethodHS256.Name},
		}
		token, err := jwtParser.Parse(value, func(t *jwt.Token) (interface{}, error) {
			secretBlock := x509.MarshalPKCS1PrivateKey(s.ServiceProvider.Key)
			return secretBlock, nil
		})
		if err != nil || !token.Valid {
			log.Debugf("... invalid token %s", err)
			continue
		}
		claims := token.Claims.(jwt.MapClaims)
		reqIDs = append(reqIDs, claims["id"].(string))
		/*
			HandleSamlLogin sets relayState per request, which contains the URI of the request. This URI has the redirectBackBase and
			RedirectBackPath values. So we can get the redirectBackBase and redirectBackPath for the current login request from URI of
			relayState
		*/
		redirectURI := claims["uri"].(string)
		log.Debugf("redirectURI from claims: %v", redirectURI)
		query, err := url.Parse(redirectURI)
		if err != nil {
			log.Errorf("Error in getting query params")
			return []string{}, "", "", fmt.Errorf("Error in getting query params: %v", err)
		}
		parsedQuery, err := url.ParseQuery(query.RawQuery)
		if err != nil {
			log.Errorf("Error in parsing query params")
			return []string{}, "", "", fmt.Errorf("Error in parsing query params: %v", err)
		}
		redirectBackBaseValue = parsedQuery.Get(redirectBackBase)
		redirectBackPathValue = parsedQuery.Get(redirectBackPath)
		log.Debugf("redirectBackBaseValue, redirectBackPathValue from claims: %v, %v", redirectBackBaseValue, redirectBackPathValue)
	}
	return reqIDs, redirectBackBaseValue, redirectBackPathValue, nil
}

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// HandleSamlAssertion processes/handles the assertion obtained by the POST to /saml/acs from IdP
func HandleSamlAssertion(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion, serviceProvider *model.RancherSamlServiceProvider,
	redirectBackBaseValue string, redirectBackPathValue string) {

	if redirectBackBaseValue == "" {
		redirectBackBaseValue = server.GetRancherAPIHost()
	}

	redirectURL := server.GetSamlRedirectURL(redirectBackBaseValue, redirectBackPathValue)

	if !isWhitelisted(redirectBackBaseValue, serviceProvider.RedirectWhitelist) {
		log.Errorf("Cannot redirect to anything other than whitelisted domains and rancher api host")
		redirectURL := server.GetSamlRedirectURL(server.GetRancherAPIHost(), redirectBackPathValue)
		redirectURL = addErrorToRedirect(redirectURL, "422")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	samlData := make(map[string][]string)

	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			attrName := attr.FriendlyName
			if attrName == "" {
				attrName = attr.Name
			}
			for _, value := range attr.Values {
				samlData[attrName] = append(samlData[attrName], value.Value)
			}
		}
	}

	rancherAPI := server.GetRancherAPIHost()
	//get the SAML data, create a jwt token and POST to /v1/token with code = "jwt token"
	mapB, _ := json.Marshal(samlData)

	inputJSON := make(map[string]string)
	inputJSON["code"] = string(mapB)
	outputJSON := make(map[string]interface{})

	tokenURL := rancherAPI + "/v1/token"
	log.Debugf("HandleSamlAssertion: tokenURL %v ", tokenURL)

	err := server.RancherClient.Post(tokenURL, inputJSON, &outputJSON)
	if err != nil {
		//failed to get token from cattle
		log.Errorf("HandleSamlAssertion failed to Get token from cattle with error %v", err.Error())
		if strings.Contains(err.Error(), "401") {
			//add error=401 query param to redirect
			redirectURL = addErrorToRedirect(redirectURL, "401")
		} else if strings.Contains(err.Error(), "403") {
			redirectURL = addErrorToRedirect(redirectURL, "403")
		} else {
			redirectURL = addErrorToRedirect(redirectURL, "500")
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	jwt := outputJSON["jwt"].(string)
	log.Debugf("HandleSamlAssertion: Got token %v ", jwt)

	secure := false
	XForwardedProtoValue := serviceProvider.XForwardedProto
	if XForwardedProtoValue == "https" {
		secure = true
	}

	/* token is created at this point. If the redirectBackBase is not same as the current URL's domain, then we cannot set the token as cookie
	yet. So we will first send a 200 POST to /v1-auth/saml/tokenhtml, which will contain token cookie and redirectBackBase in HTML body,
	and JS which will submit form on load to redirect URL. The handler for v1-auth/saml/tokenhtml will then set the token as cookie
	*/

	query, err := url.Parse(redirectBackBaseValue)
	if err != nil {
		log.Errorf("HandleSamlAssertion: Error in parsing redirectBackBaseValue: %v", err)
		redirectURL = addErrorToRedirect(redirectURL, "500")
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	log.Debugf("HandleSamlAssertion: r.URL: %v, host: %v, redirectBackBaseValue: %v, redirectBackBaseValue.host: %v", r.URL, r.Host, redirectBackBaseValue,
		query.Host)
	if query.Host != r.Host {
		newRedirectURL := redirectBackBaseValue + postSamlTokenHTML
		w.Header().Add("Content-type", "text/html")

		tmpl := template.Must(template.New("saml-post-form").Parse(tpl))
		data := struct {
			URL              string
			Token            string
			FinalRedirectURL string
			Secure           bool
		}{
			URL:              newRedirectURL,
			Token:            jwt,
			FinalRedirectURL: redirectURL,
			Secure:           secure,
		}

		log.Debugf("HandleSamlAssertion: Adding data to template: %#v", data)
		rv := bytes.Buffer{}
		if err := tmpl.Execute(&rv, data); err != nil {
			redirectURL = addErrorToRedirect(redirectURL, "500")
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		w.Write(rv.Bytes())
		return
	}

	// else, if redirectBackBase is same as the current URL, continue and set this token as cookie
	tokenCookie := &http.Cookie{
		Name:   "token",
		Value:  jwt,
		Secure: secure,
		MaxAge: 0,
		Path:   "/",
	}
	http.SetCookie(w, tokenCookie)
	log.Debugf("JWT token: %v", jwt)
	log.Debugf("redirecting the user with cookie %v to %v", tokenCookie, redirectURL)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return
}

func PostSamlTokenHTML(w http.ResponseWriter, r *http.Request) {
	var token, finalRedirectURL string
	var secure bool
	var err error

	if err = r.ParseForm(); err != nil {
		log.Errorf("PostSamlTokenHTML: Error in parsing forn: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	tokenArr, ok := r.Form["token"]
	if !ok || len(tokenArr) == 0 {
		log.Errorf("PostSamlTokenHTML: No token provided in POST request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	token = tokenArr[0]
	log.Debugf("PostSamlTokenHTML: token in the post form: %v", token)

	finalRedirectURLArr, ok := r.Form["finalRedirectURL"]
	if !ok || len(finalRedirectURLArr) == 0 {
		log.Errorf("PostSamlTokenHTML: No finalRedirectURL provided in POST request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	finalRedirectURL = finalRedirectURLArr[0]
	log.Debugf("PostSamlTokenHTML: finalRedirectURL in the post form: %v", finalRedirectURL)

	secureArr, ok := r.Form["secure"]
	if !ok || len(secureArr) == 0 {
		log.Errorf("PostSamlTokenHTML: No secure parameter provided in POST request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	secureStr := secureArr[0]
	secure, err = strconv.ParseBool(secureStr)
	if err != nil {
		log.Errorf("PostSamlTokenHTML: Error in parsing secure flag for token: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Debugf("PostSamlTokenHTML: secure attribute in the post form: %v, and original: %v", secure, secureStr)

	tokenCookie := &http.Cookie{
		Name:   "token",
		Value:  token,
		Secure: secure,
		MaxAge: 0,
		Path:   "/",
	}
	http.SetCookie(w, tokenCookie)
	log.Debugf("redirecting the user with cookie %v to %v", tokenCookie, finalRedirectURL)

	http.Redirect(w, r, finalRedirectURL, http.StatusFound)
}

func isWhitelisted(redirectBackBaseValue string, redirectWhitelist string) bool {
	var redirectBackBaseDomainNonPort string
	if redirectBackBaseValue == server.GetRancherAPIHost() {
		return true
	}
	redirectURL, err := url.Parse(redirectBackBaseValue)
	if err != nil {
		log.Errorf("Error in parsing redirect URL")
		return false
	}
	redirectBackBaseDomain := redirectURL.Host
	if strings.Contains(redirectBackBaseDomain, ":") {
		d := strings.SplitN(redirectBackBaseDomain, ":", 2)
		redirectBackBaseDomainNonPort = d[0]
	}

	// comma separated list of whitelisted domains to redirect to
	if redirectWhitelist != "" {
		whitelistedDomains := strings.Split(redirectWhitelist, ",")
		log.Debugf("Whitelisted domains provided: %v, redirectBackBase: %v, redirectBackBaseNonPort: %v", whitelistedDomains,
			redirectBackBaseDomain, redirectBackBaseDomainNonPort)
		for _, w := range whitelistedDomains {
			if w == redirectBackBaseDomain || w == redirectBackBaseDomainNonPort {
				log.Debugf("Whitelisted domain matched: %v", w)
				return true
			}
		}
	}
	return false
}
