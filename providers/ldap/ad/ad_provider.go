package ldap

import (
	"crypto/x509"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	v1client "github.com/rancher/go-rancher/client"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers/ldap"
)

const (
	Name                            = "ldap"
	UserScope                       = Name + "_user"
	GroupScope                      = Name + "_group"
	Config                          = Name + "config"
	LdapJwt                         = Name + "Jwt"
	MemberOfAttribute               = "memberOf"
	ObjectClassAttribute            = "objectClass"
	settingBase                     = "api.auth.ldap."
	AccessModeSetting               = settingBase + "access.mode"
	DomainSetting                   = settingBase + "domain"
	GroupSearchDomainSetting        = settingBase + "group.search.domain"
	LoginDomainSetting              = settingBase + "login.domain"
	PortSetting                     = settingBase + "port"
	UserSearchFieldSetting          = settingBase + "user.search.field"
	ServiceAccountUsernameSetting   = settingBase + "service.account.user"
	GroupSearchFieldSetting         = settingBase + "group.search.field"
	UserObjectClassSetting          = settingBase + "user.object.class"
	UserNameFieldSetting            = settingBase + "user.name.field"
	GroupObjectClassSetting         = settingBase + "group.object.class"
	UserLoginFieldSetting           = settingBase + "user.login.field"
	UserDisabledBitMaskSetting      = settingBase + "user.enabled.mask.bit"
	ServerSetting                   = settingBase + "server"
	ServiceAccountPasswordSetting   = settingBase + "service.account.password"
	UserEnabledAttributeSetting     = settingBase + "user.enabled.attribute"
	GroupNameFieldSetting           = settingBase + "group.name.field"
	TLSSetting                      = settingBase + "tls"
	TimeoutSetting                  = settingBase + "connection.timeout"
	AllowedIdentitiesSetting        = settingBase + "allowed.identities"
	GroupDnFieldSetting             = settingBase + "group.dn.field"
	GroupMemberUserAttributeSetting = settingBase + "group.member.user.attribute"
)

var scopes = []string{UserScope, GroupScope}

type ADProvider struct {
	LdapClient *ldap.LClient
}

var adConstantsConfig = &ldap.ConstantsConfig{
	UserScope:            UserScope,
	GroupScope:           GroupScope,
	Scopes:               scopes,
	MemberOfAttribute:    MemberOfAttribute,
	ObjectClassAttribute: ObjectClassAttribute,
	LdapJwt:              LdapJwt,
}

func InitializeProvider() (*ADProvider, error) {
	ldapClient := &ldap.LClient{}
	ldapProvider := &ADProvider{}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "Error in loading certs")
	}
	adConstantsConfig.CAPool = pool
	ldapClient.ConstantsConfig = adConstantsConfig
	ldapProvider.LdapClient = ldapClient

	return ldapProvider, nil
}

func (a *ADProvider) GetName() string {
	return Name
}

func (a *ADProvider) GetUserType() string {
	return UserScope
}

func (a *ADProvider) GenerateToken(jsonInput map[string]string) (model.Token, int, error) {
	return a.LdapClient.GenerateToken(jsonInput)
}

func (a *ADProvider) GetIdentity(distinguishedName string, scope string, accessToken string) (client.Identity, error) {
	return a.LdapClient.GetIdentity(distinguishedName, scope)
}

//SearchIdentities returns the identity by name
func (a *ADProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	return a.LdapClient.SearchIdentities(name, exactMatch)
}

//GetSettings transforms the provider config to db settings
func (a *ADProvider) GetSettings() map[string]string {
	settings := make(map[string]string)

	settings[DomainSetting] = a.LdapClient.Config.Domain
	settings[GroupSearchDomainSetting] = a.LdapClient.Config.GroupSearchDomain
	settings[LoginDomainSetting] = a.LdapClient.Config.LoginDomain
	settings[PortSetting] = strconv.FormatInt(a.LdapClient.Config.Port, 10)
	settings[UserSearchFieldSetting] = a.LdapClient.Config.UserSearchField
	settings[ServiceAccountUsernameSetting] = a.LdapClient.Config.ServiceAccountUsername
	settings[GroupSearchFieldSetting] = a.LdapClient.Config.GroupSearchField
	settings[UserObjectClassSetting] = a.LdapClient.Config.UserObjectClass
	settings[UserNameFieldSetting] = a.LdapClient.Config.UserNameField
	settings[GroupObjectClassSetting] = a.LdapClient.Config.GroupObjectClass
	settings[UserLoginFieldSetting] = a.LdapClient.Config.UserLoginField
	settings[UserDisabledBitMaskSetting] = strconv.FormatInt(a.LdapClient.Config.UserDisabledBitMask, 10)
	settings[ServerSetting] = a.LdapClient.Config.Server
	if a.LdapClient.Config.ServiceAccountPassword != "" {
		settings[ServiceAccountPasswordSetting] = a.LdapClient.Config.ServiceAccountPassword
	}
	settings[UserEnabledAttributeSetting] = a.LdapClient.Config.UserEnabledAttribute
	settings[GroupNameFieldSetting] = a.LdapClient.Config.GroupNameField
	settings[TLSSetting] = strconv.FormatBool(a.LdapClient.Config.TLS)
	settings[TimeoutSetting] = strconv.FormatInt(a.LdapClient.Config.ConnectionTimeout, 10)
	settings[GroupDnFieldSetting] = a.LdapClient.Config.GroupDNField
	settings[GroupMemberUserAttributeSetting] = a.LdapClient.Config.GroupMemberUserAttribute

	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (a *ADProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	ldapConfig := model.LdapConfig{Resource: client.Resource{
		Type: "ldapconfig",
	}}
	ldapConfig.Domain = providerSettings[DomainSetting]
	ldapConfig.GroupSearchDomain = providerSettings[GroupSearchDomainSetting]
	ldapConfig.LoginDomain = providerSettings[LoginDomainSetting]
	port, err := strconv.ParseInt(providerSettings[PortSetting], 10, 64)
	if err != nil {
		log.Errorf("Error in updating config %v", err)
		ldapConfig.Port = 389
	} else {
		ldapConfig.Port = port
	}
	ldapConfig.UserSearchField = providerSettings[UserSearchFieldSetting]
	ldapConfig.ServiceAccountUsername = providerSettings[ServiceAccountUsernameSetting]
	ldapConfig.GroupSearchField = providerSettings[GroupSearchFieldSetting]
	ldapConfig.UserObjectClass = providerSettings[UserObjectClassSetting]
	ldapConfig.GroupObjectClass = providerSettings[GroupObjectClassSetting]
	ldapConfig.UserNameField = providerSettings[UserNameFieldSetting]
	ldapConfig.GroupNameField = providerSettings[GroupNameFieldSetting]
	ldapConfig.UserLoginField = providerSettings[UserLoginFieldSetting]
	userDisabledBitMask, err := strconv.ParseInt(providerSettings[UserDisabledBitMaskSetting], 10, 64)
	if err != nil {
		log.Errorf("Error in updating config %v", err)
		ldapConfig.UserDisabledBitMask = 2
	} else {
		ldapConfig.UserDisabledBitMask = userDisabledBitMask
	}
	ldapConfig.Server = providerSettings[ServerSetting]
	ldapConfig.ServiceAccountPassword = providerSettings[ServiceAccountPasswordSetting]
	ldapConfig.UserEnabledAttribute = providerSettings[UserEnabledAttributeSetting]
	tls, err := strconv.ParseBool(providerSettings[TLSSetting])
	if err != nil {
		log.Errorf("Error in updating config %v", err)
	}
	ldapConfig.TLS = tls
	connectionTimeout, err := strconv.ParseInt(providerSettings[TimeoutSetting], 10, 64)
	if err != nil {
		log.Errorf("Error in updating config %v", err)
		ldapConfig.ConnectionTimeout = 5
	} else {
		ldapConfig.ConnectionTimeout = connectionTimeout
	}
	ldapConfig.GroupDNField = providerSettings[GroupDnFieldSetting]
	ldapConfig.GroupMemberUserAttribute = providerSettings[GroupMemberUserAttributeSetting]

	authConfig.LdapConfig = ldapConfig
}

//GetProviderSettingList returns the provider specific db setting list
func (a *ADProvider) GetProviderSettingList(listOnly bool) []string {
	var settings []string

	settings = append(settings, DomainSetting)
	settings = append(settings, GroupSearchDomainSetting)
	settings = append(settings, LoginDomainSetting)
	settings = append(settings, PortSetting)
	settings = append(settings, UserSearchFieldSetting)
	settings = append(settings, ServiceAccountUsernameSetting)
	settings = append(settings, GroupSearchFieldSetting)
	settings = append(settings, UserObjectClassSetting)
	settings = append(settings, UserNameFieldSetting)
	settings = append(settings, GroupObjectClassSetting)
	settings = append(settings, UserLoginFieldSetting)
	settings = append(settings, UserDisabledBitMaskSetting)
	settings = append(settings, ServerSetting)
	settings = append(settings, UserEnabledAttributeSetting)
	settings = append(settings, GroupNameFieldSetting)
	settings = append(settings, TLSSetting)
	settings = append(settings, TimeoutSetting)
	settings = append(settings, GroupDnFieldSetting)
	settings = append(settings, GroupMemberUserAttributeSetting)
	if !listOnly {
		settings = append(settings, ServiceAccountPasswordSetting)
	}

	return settings
}

//GetLegacySettings returns the provider specific legacy db settings
func (a *ADProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	settings["accessModeSetting"] = AccessModeSetting
	settings["allowedIdentitiesSetting"] = AllowedIdentitiesSetting
	return settings
}

//GetConfig returns the provider config
func (a *ADProvider) GetConfig() model.AuthConfig {
	log.Debug("In LDAP getConfig")

	authConfig := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	authConfig.Provider = Config
	authConfig.LdapConfig = *a.LdapClient.Config

	authConfig.LdapConfig.Resource = client.Resource{
		Type: "ldapconfig",
	}

	log.Debug("In LDAP authConfig %v", authConfig)
	return authConfig
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (a *ADProvider) GetIdentitySeparator() string {
	return ldap.GetIdentitySeparator()
}

// LoadConfig initializes the provider with the passed config
func (a *ADProvider) LoadConfig(authConfig *model.AuthConfig) error {
	configObj := authConfig.LdapConfig
	a.LdapClient.Config = &configObj
	a.LdapClient.AccessMode = authConfig.AccessMode
	a.LdapClient.AllowedIdentities = getAllowedIDString(authConfig.AllowedIdentities, a.GetIdentitySeparator())
	a.LdapClient.ConstantsConfig = adConstantsConfig
	a.LdapClient.SearchConfig = a.LdapClient.InitializeSearchConfig()
	a.LdapClient.Enabled = authConfig.Enabled
	return nil
}

//RefreshToken re-authenticates and generate a new token
func (a *ADProvider) RefreshToken(json map[string]string) (model.Token, int, error) {
	return a.LdapClient.RefreshToken(json)
}

//GetIdentities returns list of user and group identities associated to this token
func (a *ADProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity
	log.Infof("%s IdentityProvider does not support GetIdentities API", Name)

	return identities, nil
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (a *ADProvider) GetRedirectURL() string {
	return ""
}

func (a *ADProvider) TestLogin(testAuthConfig *model.TestAuthConfig) (int, error) {
	return a.LdapClient.TestLogin(testAuthConfig)
}

func (a *ADProvider) GetProviderConfigResource() interface{} {
	return model.LdapConfig{}
}

func (a *ADProvider) CustomizeSchema(schema *v1client.Schema) *v1client.Schema {
	port := schema.ResourceFields["port"]
	port.Default = 389
	schema.ResourceFields["port"] = port

	userSearchField := schema.ResourceFields["userSearchField"]
	userSearchField.Default = "sAMAccountName"
	schema.ResourceFields["userSearchField"] = userSearchField

	groupSearchField := schema.ResourceFields["groupSearchField"]
	groupSearchField.Default = "sAMAccountName"
	schema.ResourceFields["groupSearchField"] = groupSearchField

	userObjectClass := schema.ResourceFields["userObjectClass"]
	userObjectClass.Default = "person"
	schema.ResourceFields["userObjectClass"] = userObjectClass

	groupObjectClass := schema.ResourceFields["groupObjectClass"]
	groupObjectClass.Default = "group"
	schema.ResourceFields["groupObjectClass"] = groupObjectClass

	userNameField := schema.ResourceFields["userNameField"]
	userNameField.Default = "name"
	schema.ResourceFields["userNameField"] = userNameField

	groupNameField := schema.ResourceFields["groupNameField"]
	groupNameField.Default = "name"
	schema.ResourceFields["groupNameField"] = groupNameField

	userLoginField := schema.ResourceFields["userLoginField"]
	userLoginField.Default = "sAMAccountName"
	schema.ResourceFields["userLoginField"] = userLoginField

	userDisabledBitMask := schema.ResourceFields["userDisabledBitMask"]
	userDisabledBitMask.Default = 2
	schema.ResourceFields["userDisabledBitMask"] = userDisabledBitMask

	userEnabledAttribute := schema.ResourceFields["userEnabledAttribute"]
	userEnabledAttribute.Default = "userAccountControl"
	schema.ResourceFields["userEnabledAttribute"] = userEnabledAttribute

	connectionTimeout := schema.ResourceFields["connectionTimeout"]
	connectionTimeout.Default = 5
	schema.ResourceFields["connectionTimeout"] = connectionTimeout

	groupDNField := schema.ResourceFields["groupDNField"]
	groupDNField.Default = "distinguishedName"
	schema.ResourceFields["groupDNField"] = groupDNField

	groupMemberUserAttribute := schema.ResourceFields["groupMemberUserAttribute"]
	groupMemberUserAttribute.Default = "distinguishedName"
	schema.ResourceFields["groupMemberUserAttribute"] = groupMemberUserAttribute

	return schema
}

func (a *ADProvider) GetProviderSecretSettings() []string {
	var settings []string
	settings = append(settings, ServiceAccountPasswordSetting)
	return settings
}

func getAllowedIDString(allowedIdentities []client.Identity, separator string) string {
	if len(allowedIdentities) > 0 {
		var idArray []string
		for _, identity := range allowedIdentities {
			identityID := identity.ExternalIdType + ":" + identity.ExternalId
			idArray = append(idArray, identityID)
		}
		return strings.Join(idArray, separator)
	}
	return ""
}

func (a *ADProvider) IsIdentityLookupSupported() bool {
	return true
}
