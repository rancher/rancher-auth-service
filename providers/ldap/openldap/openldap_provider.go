package openldap

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
	Name                               = "openldap"
	UserScope                          = Name + "_user"
	GroupScope                         = Name + "_group"
	Config                             = Name + "config"
	LdapJwt                            = Name + "Jwt"
	MemberOfAttribute                  = "memberOf"
	ObjectClassAttribute               = "objectClass"
	settingBase                        = "api.auth.ldap.openldap."
	AccessModeSetting                  = settingBase + "access.mode"
	DomainSetting                      = settingBase + "domain"
	GroupSearchDomainSetting           = settingBase + "group.search.domain"
	LoginDomainSetting                 = settingBase + "login.domain"
	PortSetting                        = settingBase + "port"
	UserSearchFieldSetting             = settingBase + "user.search.field"
	ServiceAccountUsernameSetting      = settingBase + "service.account.user"
	GroupSearchFieldSetting            = settingBase + "group.search.field"
	UserObjectClassSetting             = settingBase + "user.object.class"
	UserNameFieldSetting               = settingBase + "user.name.field"
	GroupObjectClassSetting            = settingBase + "group.object.class"
	UserLoginFieldSetting              = settingBase + "user.login.field"
	UserDisabledBitMaskSetting         = settingBase + "user.enabled.mask.bit"
	ServerSetting                      = settingBase + "server"
	ServiceAccountPasswordSetting      = settingBase + "service.account.password"
	UserEnabledAttributeSetting        = settingBase + "user.enabled.attribute"
	GroupNameFieldSetting              = settingBase + "group.name.field"
	TLSSetting                         = settingBase + "tls"
	TimeoutSetting                     = settingBase + "connection.timeout"
	AllowedIdentitiesSetting           = settingBase + "allowed.identities"
	GroupDnFieldSetting                = settingBase + "group.dn.field"
	UserDnFieldSetting                 = settingBase + "user.dn.field"
	UserMemberAttributeSetting         = settingBase + "user.member.attribute"
	GroupMemberUserAttributeSetting    = settingBase + "group.member.user.attribute"
	GroupMemberMappingAttributeSetting = settingBase + "group.member.mapping.attribute"
)

var scopes = []string{UserScope, GroupScope}

type OpenLdapProvider struct {
	LdapClient *ldap.LClient
}

var openLdapConstantsConfig = &ldap.ConstantsConfig{
	UserScope:            UserScope,
	GroupScope:           GroupScope,
	Scopes:               scopes,
	MemberOfAttribute:    MemberOfAttribute,
	ObjectClassAttribute: ObjectClassAttribute,
	LdapJwt:              LdapJwt,
}

func InitializeProvider() (*OpenLdapProvider, error) {
	ldapClient := &ldap.LClient{}
	ldapProvider := &OpenLdapProvider{}

	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "Error in loading certs")
	}
	openLdapConstantsConfig.CAPool = pool
	ldapClient.ConstantsConfig = openLdapConstantsConfig
	ldapProvider.LdapClient = ldapClient

	return ldapProvider, nil
}

func (o *OpenLdapProvider) GetName() string {
	return Name
}

func (o *OpenLdapProvider) GetUserType() string {
	return UserScope
}

func (o *OpenLdapProvider) GenerateToken(jsonInput map[string]string) (model.Token, int, error) {
	jsonInput["provider"] = Config
	return o.LdapClient.GenerateToken(jsonInput)
}

func (o *OpenLdapProvider) GetIdentity(distinguishedName string, scope string, accessToken string) (client.Identity, error) {
	return o.LdapClient.GetIdentity(distinguishedName, scope)
}

//SearchIdentities returns the identity by name
func (o *OpenLdapProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	return o.LdapClient.SearchIdentities(name, exactMatch)
}

//GetSettings transforms the provider config to db settings
func (o *OpenLdapProvider) GetSettings() map[string]string {
	settings := make(map[string]string)

	settings[DomainSetting] = o.LdapClient.Config.Domain
	settings[GroupSearchDomainSetting] = o.LdapClient.Config.GroupSearchDomain
	settings[LoginDomainSetting] = o.LdapClient.Config.LoginDomain
	settings[PortSetting] = strconv.FormatInt(o.LdapClient.Config.Port, 10)
	settings[UserSearchFieldSetting] = o.LdapClient.Config.UserSearchField
	settings[ServiceAccountUsernameSetting] = o.LdapClient.Config.ServiceAccountUsername
	settings[GroupSearchFieldSetting] = o.LdapClient.Config.GroupSearchField
	settings[UserObjectClassSetting] = o.LdapClient.Config.UserObjectClass
	settings[UserNameFieldSetting] = o.LdapClient.Config.UserNameField
	settings[GroupObjectClassSetting] = o.LdapClient.Config.GroupObjectClass
	settings[UserLoginFieldSetting] = o.LdapClient.Config.UserLoginField
	settings[UserDisabledBitMaskSetting] = strconv.FormatInt(o.LdapClient.Config.UserDisabledBitMask, 10)
	settings[ServerSetting] = o.LdapClient.Config.Server
	if o.LdapClient.Config.ServiceAccountPassword != "" {
		settings[ServiceAccountPasswordSetting] = o.LdapClient.Config.ServiceAccountPassword
	}
	settings[UserEnabledAttributeSetting] = o.LdapClient.Config.UserEnabledAttribute
	settings[GroupNameFieldSetting] = o.LdapClient.Config.GroupNameField
	settings[TLSSetting] = strconv.FormatBool(o.LdapClient.Config.TLS)
	settings[TimeoutSetting] = strconv.FormatInt(o.LdapClient.Config.ConnectionTimeout, 10)
	settings[GroupDnFieldSetting] = o.LdapClient.Config.GroupDNField
	settings[GroupMemberUserAttributeSetting] = o.LdapClient.Config.GroupMemberUserAttribute
	settings[GroupMemberMappingAttributeSetting] = o.LdapClient.Config.GroupMemberMappingAttribute
	settings[UserMemberAttributeSetting] = o.LdapClient.Config.UserMemberAttribute

	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (o *OpenLdapProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	ldapConfig := model.LdapConfig{Resource: client.Resource{
		Type: "openldapconfig",
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
	ldapConfig.UserMemberAttribute = providerSettings[UserMemberAttributeSetting]
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
	ldapConfig.GroupMemberMappingAttribute = providerSettings[GroupMemberMappingAttributeSetting]

	authConfig.OpenLdapConfig = ldapConfig
}

//GetProviderSettingList returns the provider specific db setting list
func (o *OpenLdapProvider) GetProviderSettingList(listOnly bool) []string {
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
	settings = append(settings, UserMemberAttributeSetting)
	settings = append(settings, TLSSetting)
	settings = append(settings, TimeoutSetting)
	settings = append(settings, GroupDnFieldSetting)
	settings = append(settings, GroupMemberUserAttributeSetting)
	settings = append(settings, GroupMemberMappingAttributeSetting)

	if !listOnly {
		settings = append(settings, ServiceAccountPasswordSetting)
	}

	return settings
}

//GetLegacySettings returns the provider specific legacy db settings
func (o *OpenLdapProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	settings["accessModeSetting"] = AccessModeSetting
	settings["allowedIdentitiesSetting"] = AllowedIdentitiesSetting
	return settings
}

//GetConfig returns the provider config
func (o *OpenLdapProvider) GetConfig() model.AuthConfig {
	log.Debug("In LDAP getConfig")

	authConfig := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	authConfig.Provider = Config
	authConfig.OpenLdapConfig = *o.LdapClient.Config

	authConfig.OpenLdapConfig.Resource = client.Resource{
		Type: "openldapconfig",
	}

	log.Infof("In LDAP authConfig %v", authConfig)
	return authConfig
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (o *OpenLdapProvider) GetIdentitySeparator() string {
	return ldap.GetIdentitySeparator()
}

// LoadConfig initializes the provider with the passed config
func (o *OpenLdapProvider) LoadConfig(authConfig *model.AuthConfig) error {
	configObj := authConfig.OpenLdapConfig
	o.LdapClient.Config = &configObj
	o.LdapClient.AccessMode = authConfig.AccessMode
	o.LdapClient.AllowedIdentities = getAllowedIDString(authConfig.AllowedIdentities, o.GetIdentitySeparator())
	o.LdapClient.ConstantsConfig = openLdapConstantsConfig
	o.LdapClient.SearchConfig = o.LdapClient.InitializeSearchConfig()
	o.LdapClient.Enabled = authConfig.Enabled

	return nil
}

//RefreshToken re-authenticates and generate a new token
func (o *OpenLdapProvider) RefreshToken(json map[string]string) (model.Token, int, error) {
	json["provider"] = Config
	return o.LdapClient.RefreshToken(json)
}

//GetIdentities returns list of user and group identities associated to this token
func (o *OpenLdapProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity
	log.Infof("%s IdentityProvider does not support GetIdentities API", Name)

	return identities, nil
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (o *OpenLdapProvider) GetRedirectURL() string {
	return ""
}

func (o *OpenLdapProvider) TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string) (int, error) {
	return o.LdapClient.TestLogin(testAuthConfig, accessToken)
}

func (o *OpenLdapProvider) GetProviderConfigResource() interface{} {
	return model.LdapConfig{}
}

func (o *OpenLdapProvider) CustomizeSchema(schema *v1client.Schema) *v1client.Schema {
	port := schema.ResourceFields["port"]
	port.Default = 389
	schema.ResourceFields["port"] = port

	userSearchField := schema.ResourceFields["userSearchField"]
	userSearchField.Default = "uid"
	schema.ResourceFields["userSearchField"] = userSearchField

	groupSearchField := schema.ResourceFields["groupSearchField"]
	groupSearchField.Default = "cn"
	schema.ResourceFields["groupSearchField"] = groupSearchField

	userObjectClass := schema.ResourceFields["userObjectClass"]
	userObjectClass.Default = "inetOrgPerson"
	schema.ResourceFields["userObjectClass"] = userObjectClass

	groupObjectClass := schema.ResourceFields["groupObjectClass"]
	groupObjectClass.Default = "groupOfNames"
	schema.ResourceFields["groupObjectClass"] = groupObjectClass

	userNameField := schema.ResourceFields["userNameField"]
	userNameField.Default = "givenName"
	schema.ResourceFields["userNameField"] = userNameField

	groupNameField := schema.ResourceFields["groupNameField"]
	groupNameField.Default = "cn"
	schema.ResourceFields["groupNameField"] = groupNameField

	userLoginField := schema.ResourceFields["userLoginField"]
	userLoginField.Default = "uid"
	schema.ResourceFields["userLoginField"] = userLoginField

	userDisabledBitMask := schema.ResourceFields["userDisabledBitMask"]
	userDisabledBitMask.Default = 0
	schema.ResourceFields["userDisabledBitMask"] = userDisabledBitMask

	userEnabledAttribute := schema.ResourceFields["userEnabledAttribute"]
	userEnabledAttribute.Default = ""
	schema.ResourceFields["userEnabledAttribute"] = userEnabledAttribute

	connectionTimeout := schema.ResourceFields["connectionTimeout"]
	connectionTimeout.Default = 5
	schema.ResourceFields["connectionTimeout"] = connectionTimeout

	userMemberAttribute := schema.ResourceFields["userMemberAttribute"]
	userMemberAttribute.Default = "memberOf"
	schema.ResourceFields["userMemberAttribute"] = userMemberAttribute

	groupDNField := schema.ResourceFields["groupDNField"]
	groupDNField.Default = "entryDN"
	schema.ResourceFields["groupDNField"] = groupDNField

	groupMemberUserAttribute := schema.ResourceFields["groupMemberUserAttribute"]
	groupMemberUserAttribute.Default = "entryDN"
	schema.ResourceFields["groupMemberUserAttribute"] = groupMemberUserAttribute

	groupMemberMappingAttribute := schema.ResourceFields["groupMemberMappingAttribute"]
	groupMemberMappingAttribute.Default = "memberUid"
	schema.ResourceFields["groupMemberMappingAttribute"] = groupMemberMappingAttribute

	return schema
}

func (o *OpenLdapProvider) GetProviderSecretSettings() []string {
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

func (o *OpenLdapProvider) IsIdentityLookupSupported() bool {
	return true
}
