package providers

import (
	"fmt"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
)

type IdentityProvider interface {
	GetName() string
	GenerateToken(securityCode string) (model.Token, error)
	RefreshToken(accessToken string) (model.Token, error)
	GetIdentities(accessToken string) ([]client.Identity, error)
	GetIdentity(externalId string, externalIdType string, accessToken string) (client.Identity, error)
	SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error)
	LoadConfig(configFilePath string) error
}

var (
	providers map[string]IdentityProvider
)

func GetProvider(name string) IdentityProvider {
	if provider, ok := providers[name]; ok {
		return provider
	}
	return nil
}

func RegisterProvider(name string, provider IdentityProvider) error {
	if providers == nil {
		providers = make(map[string]IdentityProvider)
	}
	if _, exists := providers[name]; exists {
		return fmt.Errorf("provider %s already registered", name)
	}
	providers[name] = provider
	return nil
}

func GetUserIdentity(identities []client.Identity, userType string) (client.Identity, bool) {
	for _, identity := range identities {
		if identity.ExternalIdType == userType {
			return identity, true
		}
	}
	return client.Identity{}, false
}
