package providers

import (
	v1client "github.com/rancher/go-rancher/client"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers/github"
	ad "github.com/rancher/rancher-auth-service/providers/ldap/ad"
	"github.com/rancher/rancher-auth-service/providers/shibboleth"
)

//Providers map
var Providers []string

//RegisterProviders creates object of type driver for every request
func RegisterProviders() {
	Providers = []string{"githubconfig", "shibbolethconfig", "ldapconfig"}
}

//IdentityProvider interfacse defines what methods an identity provider should implement
type IdentityProvider interface {
	GetName() string
	GetUserType() string
	GenerateToken(json map[string]string) (model.Token, int, error)
	RefreshToken(json map[string]string) (model.Token, int, error)
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
	TestLogin(testAuthConfig *model.TestAuthConfig, accessToken string) (int, error)
	GetProviderConfigResource() interface{}
	CustomizeSchema(schema *v1client.Schema) *v1client.Schema
	GetProviderSecretSettings() []string
	IsIdentityLookupSupported() bool
}

//GetProvider returns an instance of an identyityProvider by name
func GetProvider(name string) (IdentityProvider, error) {
	switch name {
	case "githubconfig":
		return github.InitializeProvider()
	case "shibbolethconfig":
		return shibboleth.InitializeProvider()
	case "ldapconfig":
		return ad.InitializeProvider()
	default:
		return nil, nil
	}
}

//IsProviderSupported returns if provider by name is supported
func IsProviderSupported(name string) bool {
	switch name {
	case "githubconfig":
		return true
	case "shibbolethconfig":
		return true
	case "ldapconfig":
		return true
	default:
		return false
	}
}
