package providers

import (
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers/github"
	"github.com/rancher/rancher-auth-service/providers/shibboleth"
)

//IdentityProvider interfacse defines what methods an identity provider should implement
type IdentityProvider interface {
	GetName() string
	GetUserType() string
	GenerateToken(json map[string]string) (model.Token, error)
	RefreshToken(json map[string]string) (model.Token, error)
	GetIdentities(accessToken string) ([]client.Identity, error)
	GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error)
	SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error)
	LoadConfig(authConfig *model.AuthConfig) error
	GetSettings() map[string]string
	GetConfig() model.AuthConfig
	GetProviderSettingList(listOnly bool) []string
	AddProviderConfig(authConfig *model.AuthConfig, providerSettings map[string]string)
	GetLegacySettings() map[string]string
	GetRedirectURL() string
	GetIdentitySeparator() string
}

//GetProvider returns an instance of an identyityProvider by name
func GetProvider(name string) IdentityProvider {
	switch name {
	case "githubconfig":
		return github.InitializeProvider()
	case "shibbolethconfig":
		return shibboleth.InitializeProvider()
	default:
		return nil
	}
}

//IsProviderSupported returns if provider by name is supported
func IsProviderSupported(name string) bool {
	switch name {
	case "githubconfig":
		return true
	case "shibbolethconfig":
		return true
	default:
		return false
	}
}
