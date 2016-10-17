package shibboleth

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
)

//Constants for shibboleth
const (
	Name                             = "shibboleth"
	Config                           = Name + "config"
	TokenType                        = Name + "jwt"
	UserType                         = Name + "_user"
	GroupType                        = Name + "_group"
	idpMetadataURLSetting            = "api.auth.shibboleth.idp.metadata.url"
	spSelfSignedCertSetting          = "api.auth.shibboleth.sp.self.signed.cert"
	spSelfSignedKeySetting           = "api.auth.shibboleth.sp.self.signed.key"
	groupsFieldSetting               = "api.auth.shibboleth.groups.field"
	displayNameSetting               = "api.auth.shibboleth.displayname.field"
	userNameSetting                  = "api.auth.shibboleth.username.field"
	uidSetting                       = "api.auth.shibboleth.object.uid.field"
	idpMetadataContentSetting        = "api.auth.shibboleth.idp.metadata.content"
	noIdentityLookupSupportedSetting = "api.auth.external.provider.no.identity.lookup"
)

func init() {
}

//InitializeProvider returns a new instance of the provider
func InitializeProvider() *SProvider {
	shibClient := &SPClient{}
	shibProvider := &SProvider{}
	shibProvider.shibClient = shibClient
	return shibProvider
}

//SProvider implements an IdentityProvider for shibboleth
type SProvider struct {
	shibClient *SPClient
}

//GetName returns the name of the provider
func (s *SProvider) GetName() string {
	return Name
}

//GetUserType returns the string used to identify a user account for this provider
func (s *SProvider) GetUserType() string {
	return UserType
}

//GenerateToken generates a token from the input json data
func (s *SProvider) GenerateToken(jsonInput map[string]string) (model.Token, error) {
	//getAccessToken
	inputMap := jsonInput["code"]
	if inputMap != "" {
		log.Debugf("%vIdentityProvider GenerateToken called for code %v", Name, inputMap)

		var samlData map[string][]string

		if err := json.Unmarshal([]byte(inputMap), &samlData); err != nil {
			log.Errorf("Error getting saml data from input %v", err)
			return model.Token{}, err
		}

		log.Debugf("samlData %v", samlData)

		var token = model.Token{Resource: client.Resource{
			Type: "token",
		}}
		var identities []client.Identity

		accounts, err := s.shibClient.getShibIdentities(samlData)
		if err != nil {
			log.Errorf("Error getting identities from saml data from Shibboleth %v", err)
			return model.Token{}, err
		}

		for _, acct := range accounts {
			shibIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			if acct.IsGroup {
				acct.toIdentity(GroupType, &shibIdentity)
			} else {
				acct.toIdentity(UserType, &shibIdentity)
			}

			identities = append(identities, shibIdentity)
		}

		log.Debugf("identities %v", identities)

		token.IdentityList = identities
		token.Type = TokenType
		user, ok := GetUserIdentity(identities, UserType)
		if !ok {
			log.Error("User identity not found from %v", Name)
			return model.Token{}, fmt.Errorf("User identity not found from %v", Name)
		}
		token.ExternalAccountID = user.ExternalId

		log.Debugf("token %v", token)
		return token, nil
	}
	return model.Token{}, fmt.Errorf("Cannot gerenate token from github, invalid request data")
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

//RefreshToken re-authenticates and generate a new token
func (s *SProvider) RefreshToken(json map[string]string) (model.Token, error) {
	log.Infof("%s IdentityProvider does not support RefreshToken API", Name)
	return model.Token{}, nil
}

//GetIdentities returns list of user and group identities associated to this token
func (s *SProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity
	log.Infof("%s IdentityProvider does not support GetIdentities API", Name)

	return identities, nil
}

//GetIdentity returns the identity by externalID and externalIDType
func (s *SProvider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	log.Infof("%s IdentityProvider does not support GetIdentity API", Name)
	identity := client.Identity{Resource: client.Resource{
		Type: "identity",
	}}
	identity.ExternalId = externalID
	identity.ExternalIdType = externalIDType
	identity.Name = externalID
	identity.Login = externalID
	return identity, nil
}

//SearchIdentities just returns an identity object by setting the name
func (s *SProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userIdentity := client.Identity{Resource: client.Resource{
		Type: "identity",
	}}
	userIdentity.ExternalId = name
	userIdentity.Resource.Id = UserType + ":" + name
	userIdentity.ExternalIdType = UserType
	userIdentity.Name = name
	userIdentity.Login = name

	identities = append(identities, userIdentity)

	return identities, nil
}

//LoadConfig initializes the provider with the passed config
func (s *SProvider) LoadConfig(authConfig *model.AuthConfig) error {
	err := s.shibClient.initializeSPClient(&authConfig.ShibbolethConfig)
	if err != nil {
		log.Errorf("Error initializing the SP client %v", err)
		return err
	}
	return nil
}

//GetConfig returns the provider config
func (s *SProvider) GetConfig() model.AuthConfig {
	log.Debug("In Shibboleth getConfig")

	authConfig := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	authConfig.Provider = Config
	authConfig.ShibbolethConfig = *s.shibClient.config

	authConfig.ShibbolethConfig.Resource = client.Resource{
		Type: "shibbolethconfig",
	}

	log.Debug("In Shibboleth authConfig %v", authConfig)
	return authConfig
}

//GetSettings transforms the provider config to db settings
func (s *SProvider) GetSettings() map[string]string {
	settings := make(map[string]string)

	settings[idpMetadataURLSetting] = s.shibClient.config.IDPMetadataURL
	settings[spSelfSignedCertSetting] = s.shibClient.config.SPSelfSignedCert
	if s.shibClient.config.SPSelfSignedKey != "" {
		settings[spSelfSignedKeySetting] = s.shibClient.config.SPSelfSignedKey
	}
	settings[groupsFieldSetting] = s.shibClient.config.GroupsField
	settings[displayNameSetting] = s.shibClient.config.DisplayNameField
	settings[userNameSetting] = s.shibClient.config.UserNameField
	settings[uidSetting] = s.shibClient.config.UIDField
	if s.shibClient.config.IDPMetadataContent != "" {
		settings[idpMetadataContentSetting] = s.shibClient.config.IDPMetadataContent
	}
	settings[noIdentityLookupSupportedSetting] = "true"

	return settings
}

//GetProviderSettingList returns the provider specific db setting list
func (s *SProvider) GetProviderSettingList(listOnly bool) []string {
	var settings []string
	settings = append(settings, idpMetadataURLSetting)
	settings = append(settings, spSelfSignedCertSetting)
	settings = append(settings, groupsFieldSetting)
	settings = append(settings, displayNameSetting)
	settings = append(settings, userNameSetting)
	settings = append(settings, uidSetting)
	settings = append(settings, noIdentityLookupSupportedSetting)
	if !listOnly {
		settings = append(settings, spSelfSignedKeySetting)
		settings = append(settings, idpMetadataContentSetting)
	}

	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (s *SProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	shibConfig := model.ShibbolethConfig{Resource: client.Resource{
		Type: "shibbolethconfig",
	}}
	shibConfig.IDPMetadataURL = providerSettings[idpMetadataURLSetting]
	shibConfig.SPSelfSignedCert = providerSettings[spSelfSignedCertSetting]
	shibConfig.SPSelfSignedKey = providerSettings[spSelfSignedKeySetting]
	shibConfig.GroupsField = providerSettings[groupsFieldSetting]
	shibConfig.DisplayNameField = providerSettings[displayNameSetting]
	shibConfig.UserNameField = providerSettings[userNameSetting]
	shibConfig.UIDField = providerSettings[uidSetting]
	shibConfig.IDPMetadataContent = providerSettings[idpMetadataContentSetting]

	authConfig.ShibbolethConfig = shibConfig
}

//GetLegacySettings returns the provider specific legacy db settings
func (s *SProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	return settings
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (s *SProvider) GetRedirectURL() string {
	//redirect to cattle UI
	path := s.shibClient.config.RancherAPIHost + "/v1-auth/saml/login"
	return path
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (s *SProvider) GetIdentitySeparator() string {
	return "#shibsaml#"
}
