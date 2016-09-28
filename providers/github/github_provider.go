package github

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"net/http"
)

//Constants for github
const (
	Name                           = "github"
	Config                         = Name + "config"
	TokenType                      = Name + "jwt"
	UserType                       = Name + "_user"
	OrgType                        = Name + "_org"
	TeamType                       = Name + "_team"
	hostnameSetting                = "api.github.domain"
	schemeSetting                  = "api.github.scheme"
	clientIDSetting                = "api.auth.github.client.id"
	clientSecretSetting            = "api.auth.github.client.secret"
	githubAccessModeSetting        = "api.auth.github.access.mode"
	githubAllowedIdentitiesSetting = "api.auth.github.allowed.identities"
)

func init() {
}

//InitializeProvider returns a new instance of the provider
func InitializeProvider() *GProvider {
	client := &http.Client{}
	githubClient := &GClient{}
	githubClient.httpClient = client

	githubProvider := &GProvider{}
	githubProvider.githubClient = githubClient

	return githubProvider
}

//GProvider implements an IdentityProvider for github
type GProvider struct {
	githubClient *GClient
}

//GetName returns the name of the provider
func (g *GProvider) GetName() string {
	return Name
}

//GetUserType returns the string used to identify a user account for this provider
func (g *GProvider) GetUserType() string {
	return UserType
}

//GenerateToken authenticates the given code and returns the token
func (g *GProvider) GenerateToken(json map[string]string) (model.Token, error) {
	//getAccessToken
	securityCode := json["code"]
	accessToken := json["accessToken"]

	if securityCode != "" {
		log.Debugf("GitHubIdentityProvider GenerateToken called for securityCode %v", securityCode)
		accessToken, err := g.githubClient.getAccessToken(securityCode)
		if err != nil {
			log.Errorf("Error generating accessToken from github %v", err)
			return model.Token{}, err
		}
		log.Debugf("Received AccessToken from github %v", accessToken)
		return g.createToken(accessToken)
	} else if accessToken != "" {
		return g.createToken(accessToken)
	} else {
		return model.Token{}, fmt.Errorf("Cannot gerenate token from github, invalid request data")
	}
}

func (g *GProvider) createToken(accessToken string) (model.Token, error) {
	var token = model.Token{Resource: client.Resource{
		Type: "token",
	}}
	token.AccessToken = accessToken
	//getIdentities from accessToken
	identities, err := g.GetIdentities(accessToken)
	if err != nil {
		log.Errorf("Error getting identities using accessToken from github %v", err)
		return model.Token{}, err
	}
	token.IdentityList = identities
	token.Type = TokenType
	user, ok := GetUserIdentity(identities, UserType)
	if !ok {
		log.Error("User identity not found using accessToken from github")
		return model.Token{}, fmt.Errorf("User identity not found using accessToken from github")
	}
	token.ExternalAccountID = user.ExternalId
	return token, nil
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
func (g *GProvider) RefreshToken(json map[string]string) (model.Token, error) {
	accessToken := json["accessToken"]
	if accessToken != "" {
		log.Debugf("GitHubIdentityProvider RefreshToken called for accessToken %v", accessToken)
		return g.createToken(accessToken)
	}
	return model.Token{}, fmt.Errorf("Cannot refresh token from github, no access token found in request")
}

//GetIdentities returns list of user and group identities associated to this token
func (g *GProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userAcct, err := g.githubClient.getGithubUser(accessToken)
	if err == nil {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		userAcct.toIdentity(UserType, &userIdentity)
		identities = append(identities, userIdentity)
	}
	orgAccts, err := g.githubClient.getGithubOrgs(accessToken)
	if err == nil {
		for _, orgAcct := range orgAccts {
			orgIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			orgAcct.toIdentity(OrgType, &orgIdentity)
			identities = append(identities, orgIdentity)
		}
	}
	teamAccts, err := g.githubClient.getGithubTeams(accessToken)
	if err == nil {
		for _, teamAcct := range teamAccts {
			teamIdentity := client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			teamAcct.toIdentity(TeamType, &teamIdentity)
			identities = append(identities, teamIdentity)
		}
	}

	return identities, nil
}

//GetIdentity returns the identity by externalID and externalIDType
func (g *GProvider) GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	identity := client.Identity{Resource: client.Resource{
		Type: "identity",
	}}

	switch externalIDType {
	case UserType:
		fallthrough
	case OrgType:
		githubAcct, err := g.githubClient.getUserOrgByID(externalID, accessToken)
		if err != nil {
			return identity, err
		}
		githubAcct.toIdentity(externalIDType, &identity)
		return identity, nil
	case TeamType:
		githubAcct, err := g.githubClient.getTeamByID(externalID, accessToken)
		if err != nil {
			return identity, err
		}
		githubAcct.toIdentity(externalIDType, &identity)
		return identity, nil
	default:
		log.Debugf("Cannot get the github account due to invalid externalIDType %v", externalIDType)
		return identity, fmt.Errorf("Cannot get the github account due to invalid externalIDType %v", externalIDType)
	}
}

//SearchIdentities returns the identity by name
func (g *GProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	var identities []client.Identity

	userAcct, err := g.githubClient.getGithubUserByName(name, accessToken)
	if err == nil {
		userIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		userAcct.toIdentity(UserType, &userIdentity)

		identities = append(identities, userIdentity)
	}

	orgAcct, err := g.githubClient.getGithubOrgByName(name, accessToken)
	if err == nil {
		orgIdentity := client.Identity{Resource: client.Resource{
			Type: "identity",
		}}
		orgAcct.toIdentity(OrgType, &orgIdentity)

		identities = append(identities, orgIdentity)
	}

	return identities, nil
}

//LoadConfig initializes the provider with the passes config
func (g *GProvider) LoadConfig(authConfig *model.AuthConfig) error {
	configObj := authConfig.GithubConfig
	g.githubClient.config = &configObj
	return nil
}

//GetConfig returns the provider config
func (g *GProvider) GetConfig() model.AuthConfig {
	log.Debug("In github getConfig")

	authConfig := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	authConfig.Provider = Config
	authConfig.GithubConfig = *g.githubClient.config

	authConfig.GithubConfig.Resource = client.Resource{
		Type: "githubconfig",
	}

	log.Debug("In github authConfig %v", authConfig)
	return authConfig
}

//GetSettings transforms the provider config to db settings
func (g *GProvider) GetSettings() map[string]string {
	settings := make(map[string]string)

	settings[hostnameSetting] = g.githubClient.config.Hostname
	settings[schemeSetting] = g.githubClient.config.Scheme
	settings[clientIDSetting] = g.githubClient.config.ClientID
	if g.githubClient.config.ClientSecret != "" {
		settings[clientSecretSetting] = g.githubClient.config.ClientSecret
	}
	return settings
}

//GetProviderSettingList returns the provider specific db setting list
func (g *GProvider) GetProviderSettingList(listOnly bool) []string {
	var settings []string
	settings = append(settings, hostnameSetting)
	settings = append(settings, schemeSetting)
	settings = append(settings, clientIDSetting)
	if !listOnly {
		settings = append(settings, clientSecretSetting)
	}
	return settings
}

//AddProviderConfig adds the provider config into the generic config using the settings from db
func (g *GProvider) AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string) {
	githubConfig := model.GithubConfig{Resource: client.Resource{
		Type: "githubconfig",
	}}
	githubConfig.Hostname = providerSettings[hostnameSetting]
	githubConfig.Scheme = providerSettings[schemeSetting]
	githubConfig.ClientID = providerSettings[clientIDSetting]
	githubConfig.ClientSecret = providerSettings[clientSecretSetting]

	authConfig.GithubConfig = githubConfig
}

//GetLegacySettings returns the provider specific legacy db settings
func (g *GProvider) GetLegacySettings() map[string]string {
	settings := make(map[string]string)
	settings["accessModeSetting"] = githubAccessModeSetting
	settings["allowedIdentitiesSetting"] = githubAllowedIdentitiesSetting
	return settings
}

//GetRedirectURL returns the provider specific redirect URL used by UI
func (g *GProvider) GetRedirectURL() string {
	redirect := ""
	if g.githubClient.config.Hostname != "" {
		redirect = g.githubClient.config.Scheme + g.githubClient.config.Hostname
	} else {
		redirect = githubDefaultHostName
	}
	redirect = redirect + "/login/oauth/authorize?client_id=" + g.githubClient.config.ClientID + "&scope=read:org"

	return redirect
}

//GetIdentitySeparator returns the provider specific separator to use to separate allowedIdentities
func (g *GProvider) GetIdentitySeparator() string {
	return ","
}
