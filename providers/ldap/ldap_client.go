package ldap

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"gopkg.in/ldap.v2"
)

// LClient is the ldap client
type LClient struct {
	Config            *model.LdapConfig
	ConstantsConfig   *ConstantsConfig
	SearchConfig      *SearchConfig
	AccessMode        string
	AllowedIdentities string
	Enabled           bool
}

type SearchConfig struct {
	Server               string
	Port                 int64
	BindDN               string
	BindPassword         string
	UserSearchAttributes []string
	GroupSeachAttributes []string
}

type ConstantsConfig struct {
	UserScope            string
	GroupScope           string
	Scopes               []string
	MemberOfAttribute    string
	ObjectClassAttribute string
	LdapJwt              string
	CAPool               *x509.CertPool
}

var nilIdentity = client.Identity{Resource: client.Resource{
	Type: "identity",
}}
var nilToken = model.Token{Resource: client.Resource{
	Type: "token",
}}

func (l *LClient) InitializeSearchConfig() *SearchConfig {
	c := l.ConstantsConfig
	return &SearchConfig{
		Server:       l.Config.Server,
		Port:         l.Config.Port,
		BindDN:       l.Config.ServiceAccountUsername,
		BindPassword: l.Config.ServiceAccountPassword,
		UserSearchAttributes: []string{c.MemberOfAttribute,
			c.ObjectClassAttribute,
			l.Config.UserObjectClass,
			l.Config.UserLoginField,
			l.Config.UserNameField,
			l.Config.UserSearchField,
			l.Config.UserEnabledAttribute},
		GroupSeachAttributes: []string{c.MemberOfAttribute,
			c.ObjectClassAttribute,
			l.Config.GroupObjectClass,
			l.Config.UserLoginField,
			l.Config.GroupNameField,
			l.Config.GroupSearchField},
	}
}

func (l *LClient) newConn() (*ldap.Conn, error) {
	log.Debug("Now creating Ldap connection")
	var lConn *ldap.Conn
	var err error
	var tlsConfig *tls.Config
	searchConfig := l.SearchConfig
	ldap.DefaultTimeout = time.Duration(l.Config.ConnectionTimeout) * time.Millisecond
	if l.Config.TLS {
		tlsConfig = &tls.Config{RootCAs: l.ConstantsConfig.CAPool, InsecureSkipVerify: false, ServerName: l.Config.Server}
		lConn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", searchConfig.Server, searchConfig.Port), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("Error creating ssl connection: %v", err)
		}
	} else {
		lConn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", searchConfig.Server, searchConfig.Port))
		if err != nil {
			return nil, fmt.Errorf("Error creating connection: %v", err)
		}
	}

	lConn.SetTimeout(time.Duration(l.Config.ConnectionTimeout) * time.Millisecond)

	return lConn, nil
}

// GenerateToken generates token
func (l *LClient) GenerateToken(jsonInput map[string]string) (model.Token, int, error) {
	log.Info("Now generating Ldap token")
	searchConfig := l.SearchConfig

	var status int

	split := strings.Split(jsonInput["code"], ":")
	provider := jsonInput["provider"]
	lConn, err := l.newConn()
	if err != nil {
		return nilToken, status, err
	}

	username, password := split[0], split[1]
	externalID := getUserExternalID(username, l.Config.LoginDomain)

	if password == "" {
		status = 401
		return nilToken, status, fmt.Errorf("Failed to login, password not provided")
	}

	switch provider {
	case "ldapconfig":
		// getLdapToken:ADTokenCreator
		// getIdentities: ADIdentityProvider
		if !l.Enabled {
			log.Debug("Bind service account username password")
			if l.SearchConfig.BindPassword == "" {
				status = 401
				return nilToken, status, fmt.Errorf("Failed to login, service account password not provided")
			}
			sausername := getUserExternalID(l.SearchConfig.BindDN, l.Config.LoginDomain)
			err = lConn.Bind(sausername, l.SearchConfig.BindPassword)

			if err != nil {
				if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
					status = 401
				}
				defer lConn.Close()
				return nilToken, status, fmt.Errorf("Error in ldap bind of service account: %v", err)
			}
		}

		log.Debug("Binding username password")
		err = lConn.Bind(externalID, password)

		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				status = 401
			}
			return nilToken, status, fmt.Errorf("Error in ldap bind: %v", err)
		}
		defer lConn.Close()
		samName := username
		if strings.Contains(username, "\\") {
			samName = strings.SplitN(username, "\\\\", 2)[1]
		}
		query := "(" + l.Config.UserLoginField + "=" + samName + ")"
		if l.AccessMode == "required" {
			groupFilter, err := l.getAllowedIdentitiesFilter()
			if err != nil {
				return nilToken, status, err
			}
			if len(groupFilter) > 1 {
				groupQuery := "(&" + query + groupFilter + ")"
				query = groupQuery
			}
			search := ldap.NewSearchRequest(l.Config.Domain,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				query,
				searchConfig.UserSearchAttributes, nil)
			result, err := lConn.Search(search)
			if err != nil {
				return nilToken, status, err
			}

			if len(result.Entries) < 1 {
				return nilToken, 403, errors.Errorf("Cannot locate user information for %s", search.Filter)
			} else if len(result.Entries) > 1 {
				return nilToken, 403, errors.New("More than one result")
			}
		}

		log.Debugf("LDAP Search query: {%s}", query)
		search := ldap.NewSearchRequest(l.Config.Domain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,
			searchConfig.UserSearchAttributes, nil)

		return l.userRecord(search, lConn)

	case "openldapconfig":
		// getLdapToken:OpenLdapTokenCreator
		// getIdentities: OpenLdapIdentityProvider
		query := "(&(" + l.Config.UserLoginField + "=" + username + ")(" + l.ConstantsConfig.ObjectClassAttribute + "=" +
			l.Config.UserObjectClass + "))"

		users, err := l.searchLdap(query, l.ConstantsConfig.UserScope)
		if err != nil {
			return model.Token{}, status, err
		}
		if len(users) != 1 {
			return model.Token{}, status, errors.Errorf("Found no or multiple users for %s", username)
		}
		externalID = users[0].ExternalId

		log.Info("Binding username password")
		err = lConn.Bind(externalID, password)
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				status = 401
			}
			return nilToken, status, fmt.Errorf("Error in ldap bind: %v", err)
		}

		search := ldap.NewSearchRequest(l.Config.Domain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query, l.SearchConfig.UserSearchAttributes, nil)

		identities, err := l.getIdentities(search, lConn)
		if err != nil {
			return nilToken, status, err
		}

		return l.getToken(identities)

	default:
		return nilToken, status, errors.New("Provider not specified")
	}
}

func (l *LClient) getIdentitiesFromSearchResult(result *ldap.SearchResult) ([]client.Identity, error) {
	// getIdentities(SearchResult result): ADIdentityProvider
	c := l.ConstantsConfig
	entry := result.Entries[0]
	if !l.hasPermission(entry.Attributes, l.Config) {
		return []client.Identity{}, fmt.Errorf("Permission denied")
	}

	identityList := []client.Identity{}
	memberOf := entry.GetAttributeValues(c.MemberOfAttribute)
	user := &client.Identity{}

	log.Debugf("ADConstants userMemberAttribute() {%s}", c.MemberOfAttribute)
	log.Debugf("SearchResult memberOf attribute {%s}", memberOf)

	// isType
	isType := false
	objectClass := entry.GetAttributeValues(c.ObjectClassAttribute)
	for _, obj := range objectClass {
		if strings.EqualFold(string(obj), l.Config.UserObjectClass) {
			isType = true
		}
	}
	if !isType {
		return []client.Identity{}, nil
	}

	user, err := l.attributesToIdentity(entry.Attributes, result.Entries[0].DN, c.UserScope)
	if err != nil {
		return []client.Identity{}, err
	}
	if user != nil {
		identityList = append(identityList, *user)
	}

	if len(memberOf) != 0 {
		for _, attrib := range memberOf {
			identity, err := l.GetIdentity(attrib, c.GroupScope)
			if err != nil {
				return []client.Identity{}, err
			}
			if !reflect.DeepEqual(identity, nilIdentity) {
				identityList = append(identityList, identity)
			}
		}
	}
	return identityList, nil
}

func (l *LClient) getIdentities(search *ldap.SearchRequest, lConn *ldap.Conn) ([]client.Identity, error) {
	// getIdentities(LdapName dn): OpenLdapIdentityProvider
	identities := []client.Identity{}
	query := search.Filter
	result, err := lConn.Search(search)
	if err != nil {
		return identities, fmt.Errorf("Error %v in search query : %v\n", err, query)
	}

	if len(result.Entries) < 1 {
		return identities, fmt.Errorf("No identities can be retrieved - 1")
	} else if len(result.Entries) > 1 {
		return identities, fmt.Errorf("More than one result found - 1")
	}

	entry := result.Entries[0]
	entryAttributes := entry.Attributes

	if !l.hasPermission(entry.Attributes, l.Config) {
		return identities, fmt.Errorf("Permission denied")
	}

	operationalAttrList := []string{"1.1", "+", "*"}
	searchOperational := search
	searchOperational.Attributes = operationalAttrList

	opResult, err := lConn.Search(searchOperational)
	if err != nil {
		return identities, fmt.Errorf("Error %v in search query : %v\n", err, query)
	}

	if len(opResult.Entries) < 1 {
		return identities, fmt.Errorf("No identities can be retrieved - 2")
	} else if len(opResult.Entries) > 1 {
		return identities, fmt.Errorf("More than one result found - 2")
	}

	opAttributes := opResult.Entries[0]
	memberOf = entry.GetAttributeValues(l.Config.UserMemberAttribute)
	if len(memberOf) < 1 {
		memberOf = opAttributes.GetAttributeValues(l.Config.UserMemberAttribute)
	}
	log.Debugf("getIdentities: memberOf attribute: %s", memberOf)

	if !isType(entryAttributes, l.Config.UserObjectClass) {
		return []client.Identity{}, nil
	}

	user, err := l.attributesToIdentity(entry.Attributes, result.Entries[0].DN, l.ConstantsConfig.UserScope)
	if err != nil {
		return []client.Identity{}, err
	}
	if user != nil {
		identities = append(identities, *user)
	}

	if len(memberOf) != 0 {
		for _, attrib := range memberOf {
			query := "(&(" + l.Config.GroupDNField + "=" + attrib + ")(" + l.ConstantsConfig.ObjectClassAttribute + "=" +
				l.Config.GroupObjectClass + "))"
			identityList, err := l.searchLdap(query, l.ConstantsConfig.GroupScope)
			if err != nil {
				return []client.Identity{}, err
			}
			log.Debugf("getIdentities: memberOf attribute query: %s", query)
			identities = append(identities, identityList...)
		}
	}

	groupMemberUserAttribute := entry.GetAttributeValue(l.Config.GroupMemberUserAttribute)
	if groupMemberUserAttribute == "" {
		groupMemberUserAttribute = opAttributes.GetAttributeValue(l.Config.GroupMemberUserAttribute)
	}
	log.Debugf("getIdentities: groupMemberUserAttribute attribute: %s", groupMemberUserAttribute)

	if groupMemberUserAttribute != "" {
		query = "(&(" + l.Config.GroupMemberMappingAttribute + "=" + groupMemberUserAttribute +
			")(" + l.ConstantsConfig.ObjectClassAttribute + "=" + l.Config.GroupObjectClass + "))"
		log.Debugf("getIdentities: groupMemberUserAttribute attribute query: %s", query)
		identityList, err := l.searchLdap(query, l.ConstantsConfig.GroupScope)
		if err != nil {
			return []client.Identity{}, err
		}
		identities = append(identities, identityList...)
	}
	return identities, nil
}

func getList(identitiesStr string, separator string) []string {
	allowedIdentities := strings.Split(identitiesStr, separator)
	for index, str := range allowedIdentities {
		allowedIdentities[index] = strings.TrimSpace(str)
	}

	return allowedIdentities
}

func (l *LClient) savedIdentities(allowedIdentities []string) ([]client.Identity, error) {
	identityList := []client.Identity{}
	if len(allowedIdentities) == 0 {
		return identityList, nil
	}

	for _, id := range allowedIdentities {
		split := strings.SplitN(id, ":", 2)
		identity, err := l.GetIdentity(split[1], split[0])
		if err != nil {
			return identityList, err
		}
		if !reflect.DeepEqual(identity, nilIdentity) {
			identityList = append(identityList, identity)
		}
	}

	return identityList, nil
}

func (l *LClient) getAllowedIdentitiesFilter() (string, error) {
	c := l.ConstantsConfig
	grpFilterArr := []string{}
	memberOf := "(memberof="
	dn := "(distinguishedName="
	identitySize := 0
	identitiesStr := l.AllowedIdentities

	// fromHashSeparatedString()
	allowedIdentities := getList(identitiesStr, GetIdentitySeparator())

	// getAllowedIdentitiesFilter(l)
	identities, err := l.savedIdentities(allowedIdentities)
	if err != nil {
		return "", err
	}
	for _, identity := range identities {
		identitySize++
		if strings.EqualFold(c.GroupScope, identity.ExternalIdType) {
			grpFilterArr = append(grpFilterArr, memberOf)
		} else {
			grpFilterArr = append(grpFilterArr, dn)
		}
		grpFilterArr = append(grpFilterArr, identity.ExternalId)
		grpFilterArr = append(grpFilterArr, ")")
	}
	groupFilter := strings.Join(grpFilterArr, "")

	if identitySize > 0 {
		outer := "(|" + groupFilter + ")"
		return outer, nil
	}

	return groupFilter, nil
}

// GetIdentity gets identities
func (l *LClient) GetIdentity(distinguishedName string, scope string) (client.Identity, error) {
	//getIdentity(String distinguishedName, String scope): LDAPIdentityProvider
	c := l.ConstantsConfig
	searchConfig := l.SearchConfig
	var search *ldap.SearchRequest
	if c.Scopes[0] != scope && c.Scopes[1] != scope {
		return nilIdentity, fmt.Errorf("Invalid scope")
	}

	// getObject()
	var attributes []*ldap.AttributeTypeAndValue
	var attribs []*ldap.EntryAttribute
	object, err := ldap.ParseDN(distinguishedName)
	if err != nil {
		return nilIdentity, err
	}
	for _, rdns := range object.RDNs {
		for _, attr := range rdns.Attributes {
			attributes = append(attributes, attr)
			entryAttr := ldap.NewEntryAttribute(attr.Type, []string{attr.Value})
			attribs = append(attribs, entryAttr)
		}
	}

	if !isType(attribs, scope) && !l.hasPermission(attribs, l.Config) {
		log.Errorf("Failed to get object %s", distinguishedName)
		return nilIdentity, nil
	}

	filter := "(" + c.ObjectClassAttribute + "=*)"
	log.Debugf("Query for GetIdentity(%s): %s", distinguishedName, filter)
	lConn, err := l.newConn()
	if err != nil {
		return nilIdentity, fmt.Errorf("Error %v creating connection", err)
	}
	// Bind before query
	// If service acc bind fails, and auth is on, return identity formed using DN
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err = lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	defer lConn.Close()
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) && l.Enabled {
			user := strings.EqualFold(c.UserScope, scope)
			identity := &client.Identity{
				Resource: client.Resource{
					Type: "identity",
				},
				ExternalIdType: scope,
				ExternalId:     distinguishedName,
				Name:           distinguishedName,
				Login:          distinguishedName,
				User:           user,
			}
			identity.Resource.Id = scope + ":" + distinguishedName
			return *identity, nil
		}
		return nilIdentity, fmt.Errorf("Error in ldap bind: %v", err)
	}

	if strings.EqualFold(c.UserScope, scope) {
		search = ldap.NewSearchRequest(distinguishedName,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			searchConfig.UserSearchAttributes, nil)
	} else {
		search = ldap.NewSearchRequest(distinguishedName,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			searchConfig.GroupSeachAttributes, nil)
	}

	result, err := lConn.Search(search)
	if err != nil {
		return nilIdentity, fmt.Errorf("Error %v in search query : %v", err, filter)
	}

	if len(result.Entries) < 1 {
		return nilIdentity, fmt.Errorf("No identities can be retrieved")
	} else if len(result.Entries) > 1 {
		return nilIdentity, fmt.Errorf("More than one result found")
	}

	entry := result.Entries[0]
	entryAttributes := entry.Attributes
	if !l.hasPermission(entry.Attributes, l.Config) {
		return nilIdentity, fmt.Errorf("Permission denied")
	}

	identity, err := l.attributesToIdentity(entryAttributes, distinguishedName, scope)
	if err != nil {
		return nilIdentity, err
	}
	if identity == nil {
		return nilIdentity, fmt.Errorf("User Identity not returned for LDAP")
	}
	return *identity, nil
}

func (l *LClient) attributesToIdentity(attribs []*ldap.EntryAttribute, dnStr string, scope string) (*client.Identity, error) {
	var externalIDType, accountName, externalID, login string
	user := false

	externalID = dnStr
	externalIDType = scope
	nameFieldPresent := false
	loginFieldPresent := false

	if isType(attribs, l.Config.UserObjectClass) {
		for _, attr := range attribs {
			if attr.Name == l.Config.UserNameField {
				if len(attr.Values) != 0 {
					accountName = attr.Values[0]
				} else {
					accountName = externalID
				}
				nameFieldPresent = true
			}
			if attr.Name == l.Config.UserLoginField {
				login = attr.Values[0]
			}
		}
		if !nameFieldPresent {
			accountName = externalID
		}
		user = true
	} else if isType(attribs, l.Config.GroupObjectClass) {
		for _, attr := range attribs {
			if attr.Name == l.Config.GroupNameField {
				if len(attr.Values) != 0 {
					accountName = attr.Values[0]
				} else {
					accountName = externalID
				}
				nameFieldPresent = true
			}
			if attr.Name == l.Config.UserLoginField {
				if len(attr.Values) > 0 && attr.Values[0] != "" {
					login = attr.Values[0]
				}
				loginFieldPresent = true
			} else {
				login = accountName
			}
		}
		if !nameFieldPresent {
			accountName = externalID
		}
		if !loginFieldPresent {
			login = accountName
		}
	} else {
		log.Errorf("Failed to get attributes for %s", dnStr)
		return nil, nil
	}

	identity := &client.Identity{
		Resource: client.Resource{
			Type: "identity",
		},
		ExternalIdType: externalIDType,
		ExternalId:     externalID,
		Name:           accountName,
		Login:          login,
		User:           user,
	}
	identity.Resource.Id = externalIDType + ":" + externalID

	return identity, nil
}

func isType(search []*ldap.EntryAttribute, varType string) bool {
	for _, attrib := range search {
		if attrib.Name == "objectClass" {
			for _, val := range attrib.Values {
				if val == varType {
					return true
				}
			}
		}
	}
	log.Debugf("Failed to determine if object is type: %s", varType)
	return false
}

func GetIdentitySeparator() string {
	return "#"
}

//GetUserIdentity returns the "user" from the list of identities
func GetUserIdentity(identities []client.Identity, userType string) (client.Identity, bool) {
	for _, identity := range identities {
		if identity.ExternalIdType == userType {
			return identity, true
		}
	}
	return client.Identity{}, false
}

//SearchIdentities returns the identity by name
func (l *LClient) SearchIdentities(name string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	identities := []client.Identity{}
	for _, scope := range c.Scopes {
		identityList, err := l.searchIdentities(name, scope, exactMatch)
		if err != nil {
			return []client.Identity{}, err
		}
		identities = append(identities, identityList...)
	}
	return identities, nil
}

func (l *LClient) searchIdentities(name string, scope string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	name = escapeLDAPSearchFilter(name)
	if strings.EqualFold(c.UserScope, scope) {
		return l.searchUser(name, exactMatch)
	} else if strings.EqualFold(c.GroupScope, scope) {
		return l.searchGroup(name, exactMatch)
	} else {
		return nil, fmt.Errorf("Invalid scope")
	}
}

func (l *LClient) searchUser(name string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	var query string
	if exactMatch {
		query = "(&(" + l.Config.UserSearchField + "=" + name + ")(" + c.ObjectClassAttribute + "=" +
			l.Config.UserObjectClass + "))"
	} else {
		query = "(&(" + l.Config.UserSearchField + "=*" + name + "*)(" + c.ObjectClassAttribute + "=" +
			l.Config.UserObjectClass + "))"
	}
	log.Debugf("LDAPIdentityProvider searchUser query: %s", query)
	return l.searchLdap(query, c.UserScope)
}

func (l *LClient) searchGroup(name string, exactMatch bool) ([]client.Identity, error) {
	c := l.ConstantsConfig
	var query string
	if exactMatch {
		query = "(&(" + l.Config.GroupSearchField + "=" + name + ")(" + c.ObjectClassAttribute + "=" +
			l.Config.GroupObjectClass + "))"
	} else {
		query = "(&(" + l.Config.GroupSearchField + "=*" + name + "*)(" + c.ObjectClassAttribute + "=" +
			l.Config.GroupObjectClass + "))"
	}
	log.Debugf("LDAPIdentityProvider searchGroup query: %s", query)
	return l.searchLdap(query, c.GroupScope)
}

func (l *LClient) searchLdap(query string, scope string) ([]client.Identity, error) {
	c := l.ConstantsConfig
	searchConfig := l.SearchConfig
	identities := []client.Identity{}
	var search *ldap.SearchRequest

	searchDomain := l.Config.Domain
	if strings.EqualFold(c.UserScope, scope) {
		search = ldap.NewSearchRequest(searchDomain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,
			searchConfig.UserSearchAttributes, nil)
	} else {
		if l.Config.GroupSearchDomain != "" {
			searchDomain = l.Config.GroupSearchDomain
		}
		search = ldap.NewSearchRequest(searchDomain,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			query,
			searchConfig.GroupSeachAttributes, nil)
	}

	lConn, err := l.newConn()
	if err != nil {
		return []client.Identity{}, fmt.Errorf("Error %v creating connection", err)
	}
	// Bind before query
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err = lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	if err != nil {
		return nil, fmt.Errorf("Error %v in ldap bind", err)
	}
	defer lConn.Close()

	results, err := lConn.Search(search)
	if err != nil {
		ldapErr, ok := reflect.ValueOf(err).Interface().(*ldap.Error)
		if ok && ldapErr.ResultCode != ldap.LDAPResultNoSuchObject {
			return []client.Identity{}, fmt.Errorf("When searching ldap from /v1/identity Failed to search: %s, error: %#v", query, err)
		}
	}

	for i := 0; i < len(results.Entries); i++ {
		entry := results.Entries[i]
		identity, err := l.attributesToIdentity(entry.Attributes, results.Entries[i].DN, scope)
		if err != nil {
			return []client.Identity{}, err
		}
		identities = append(identities, *identity)
	}

	return identities, nil
}

func escapeLDAPSearchFilter(filter string) string {
	buf := new(bytes.Buffer)
	for i := 0; i < len(filter); i++ {
		currChar := filter[i]
		switch currChar {
		case '\\':
			buf.WriteString("\\5c")
			break
		case '*':
			buf.WriteString("\\2a")
			break
		case '(':
			buf.WriteString("\\28")
			break
		case ')':
			buf.WriteString("\\29")
			break
		case '\u0000':
			buf.WriteString("\\00")
			break
		default:
			buf.WriteString(string(currChar))
		}
	}
	return buf.String()
}

func (l *LClient) TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string) (int, error) {
	var lConn *ldap.Conn
	var err error
	var status int
	status = 500
	var ldapConfig model.LdapConfig
	var externalID, sausername, query string

	split := strings.Split(testAuthConfig.Code, ":")
	username, password := split[0], split[1]
	provider := testAuthConfig.AuthConfig.Provider
	if password == "" {
		return 401, fmt.Errorf("Failed to login, password not provided")
	}

	if provider == "ldapconfig" {
		externalID = getUserExternalID(username, testAuthConfig.AuthConfig.LdapConfig.LoginDomain)
		ldapConfig = testAuthConfig.AuthConfig.LdapConfig
	} else {
		ldapConfig = testAuthConfig.AuthConfig.OpenLdapConfig
	}

	ldapServer := ldapConfig.Server
	ldapPort := ldapConfig.Port

	log.Debug("TestLogin: Now creating Ldap connection")
	if ldapConfig.TLS {
		tlsConfig := &tls.Config{RootCAs: l.ConstantsConfig.CAPool, InsecureSkipVerify: false, ServerName: ldapServer}
		lConn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort), tlsConfig)
		if err != nil {
			return status, fmt.Errorf("Error creating ssl connection: %v", err)
		}
	} else {
		lConn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
		if err != nil {
			return status, fmt.Errorf("Error creating connection: %v", err)
		}
	}

	lConn.SetTimeout(time.Duration(ldapConfig.ConnectionTimeout) * time.Second)
	defer lConn.Close()

	if ldapConfig.ServiceAccountPassword == "" {
		status = 401
		return status, fmt.Errorf("Failed to login, service account password not provided")
	}

	log.Debug("TestLogin: Binding service account username password")
	if provider == "ldapconfig" {
		sausername = getUserExternalID(testAuthConfig.AuthConfig.LdapConfig.ServiceAccountUsername, testAuthConfig.AuthConfig.LdapConfig.LoginDomain)
	} else if provider == "openldapconfig" {
		sausername = ldapConfig.ServiceAccountUsername
	}
	err = lConn.Bind(sausername, ldapConfig.ServiceAccountPassword)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			status = 401
		}
		return status, fmt.Errorf("Error in ldap bind for service account: %v", err)
	}

	if provider == "ldapconfig" {
		log.Debug("TestLogin: Binding username password")
		err = lConn.Bind(externalID, password)
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				status = 401
			}
			return status, fmt.Errorf("Error in ldap bind of (%s:%s): %v", externalID, password, err)
		}

		samName := username
		if strings.Contains(username, "\\") {
			samName = strings.SplitN(username, "\\\\", 2)[1]
		}
		query = "(" + testAuthConfig.AuthConfig.LdapConfig.UserLoginField + "=" + samName + ")"
	} else {
		query = "(&(" + l.Config.UserLoginField + "=" + username + ")(" + l.ConstantsConfig.ObjectClassAttribute + "=" +
			l.Config.UserObjectClass + "))"

	}

	log.Debugf("LDAP Search query: {%s}", query)
	testUserSearchAttributes := []string{l.ConstantsConfig.MemberOfAttribute, l.ConstantsConfig.ObjectClassAttribute,
		ldapConfig.UserObjectClass, ldapConfig.UserLoginField, ldapConfig.UserNameField, ldapConfig.UserSearchField,
		ldapConfig.UserEnabledAttribute}

	search := ldap.NewSearchRequest(ldapConfig.Domain,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		query, testUserSearchAttributes, nil)

	result, err := lConn.Search(search)
	if err != nil {
		return status, fmt.Errorf("Error searching the user information with new server settings: %v", err)
	}

	if len(result.Entries) < 1 {
		return status, fmt.Errorf("Authentication succeeded, but cannot locate the user information with new server schema settings")
	} else if len(result.Entries) > 1 {
		return status, fmt.Errorf("Multiple users found for the username with new server settings")
	}

	entry := result.Entries[0]
	if !l.hasPermission(entry.Attributes, &ldapConfig) {
		return status, fmt.Errorf("Authentication succeeded, but user is probably disabled in the new server settings")
	}

	userIdentity, err := l.attributesToIdentity(entry.Attributes, entry.DN, l.ConstantsConfig.UserScope)
	if err != nil {
		return status, fmt.Errorf("Authentication succeeded, but error reading the user information with new server schema settings: %v", err)
	}

	if userIdentity == nil {
		return status, fmt.Errorf("Authentication succeeded, but cannot search user information with new server settings")
	}

	if provider == "openldapconfig" {
		externalID = userIdentity.ExternalId
		log.Info("Binding username password")
		err = lConn.Bind(externalID, password)
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				status = 401
			}
			return status, fmt.Errorf("Error in ldap bind: %v", err)
		}
	}

	if userIdentity.ExternalId != accessToken {
		return status, fmt.Errorf("Authentication succeeded, but the user returned has a different Distinguished Name than you are currently logged in to. Changing the underlying directory tree is not supported")
	}

	return status, nil
}

func getUserExternalID(username string, loginDomain string) string {
	if strings.Contains(username, "\\") {
		return username
	} else if loginDomain != "" {
		return loginDomain + "\\" + username
	}
	return username
}

func (l *LClient) hasPermission(attributes []*ldap.EntryAttribute, config *model.LdapConfig) bool {
	var permission int64
	if !isType(attributes, config.UserObjectClass) {
		return true
	}
	if config.UserEnabledAttribute == "" {
		return true
	}
	for _, attr := range attributes {
		if attr.Name == config.UserEnabledAttribute {
			if len(attr.Values) > 0 && attr.Values[0] != "" {
				intAttr, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					log.Errorf("Failed to get USER_ENABLED_ATTRIBUTE, error: %v", err)
					return false
				}
				permission = intAttr
			} else {
				return true
			}
		}
	}

	permission = permission & config.UserDisabledBitMask
	return permission != config.UserDisabledBitMask
}

func (l *LClient) RefreshToken(json map[string]string) (model.Token, int, error) {
	provider := json["provider"]
	var status int

	c := l.ConstantsConfig
	searchConfig := l.SearchConfig
	query := "(" + c.ObjectClassAttribute + "=*)"
	search := ldap.NewSearchRequest(json["accessToken"],
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		query,
		searchConfig.UserSearchAttributes, nil)

	lConn, err := l.newConn()
	if err != nil {
		return nilToken, status, fmt.Errorf("Error %v creating connection", err)
	}
	// Bind before query
	serviceAccountUsername := getUserExternalID(l.Config.ServiceAccountUsername, l.Config.LoginDomain)
	err = lConn.Bind(serviceAccountUsername, l.Config.ServiceAccountPassword)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			status = 401
		}
		return nilToken, status, fmt.Errorf("Error %v in ldap bind", err)
	}
	defer lConn.Close()

	switch provider {
	case "ldapconfig":
		return l.userRecord(search, lConn)

	case "openldapconfig":
		identities, err := l.getIdentities(search, lConn)
		if err != nil {
			return nilToken, status, err
		}
		return l.getToken(identities)

	default:
		return nilToken, status, errors.New("Provider not specified")
	}

}

func (l *LClient) userRecord(search *ldap.SearchRequest, lConn *ldap.Conn) (model.Token, int, error) {
	var status int
	c := l.ConstantsConfig
	result, err := lConn.Search(search)
	if err != nil {
		return nilToken, status, err
	}

	if len(result.Entries) < 1 {
		log.Errorf("Cannot locate user information for %s", search.Filter)
		return nilToken, status, nil
	} else if len(result.Entries) > 1 {
		log.Error("More than one result")
		return nilToken, status, nil
	}

	identityList, err := l.getIdentitiesFromSearchResult(result)
	if err != nil {
		return nilToken, status, err
	}

	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}
	token.IdentityList = identityList
	token.Type = c.LdapJwt
	userIdentity, ok := GetUserIdentity(identityList, c.UserScope)
	if !ok {
		return nilToken, status, fmt.Errorf("User identity not found for Ldap")
	}
	token.ExternalAccountID = userIdentity.ExternalId
	token.AccessToken = userIdentity.ExternalId
	return token, status, nil
}

func (l *LClient) getToken(identities []client.Identity) (model.Token, int, error) {
	var status int
	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}
	token.IdentityList = identities
	token.Type = l.ConstantsConfig.LdapJwt
	userIdentity, ok := GetUserIdentity(identities, l.ConstantsConfig.UserScope)
	if !ok {
		return nilToken, status, fmt.Errorf("User identity not found for Ldap")
	}
	token.ExternalAccountID = userIdentity.ExternalId
	token.AccessToken = userIdentity.ExternalId
	return token, status, nil
}
