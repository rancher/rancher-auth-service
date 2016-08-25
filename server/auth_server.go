package server

import (
	"crypto/rsa"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/urfave/cli"
	"strconv"
	"strings"

	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers"
	"github.com/rancher/rancher-auth-service/util"
)

const (
	accessModeSetting        = "api.auth.access.mode"
	allowedIdentitiesSetting = "api.auth.allowed.identities"
	userTypeSetting          = "api.auth.user.type"
	providerSetting          = "api.auth.provider.configured"
	providerNameSetting      = "api.auth.provider.name.configured"
	externalProviderSetting  = "api.auth.external.provider.configured"
	securitySetting          = "api.security.enabled"
)

var (
	provider                                                                     providers.IdentityProvider
	privateKey                                                                   *rsa.PrivateKey
	publicKey                                                                    *rsa.PublicKey
	authConfigInMemory                                                           model.AuthConfig
	rancherClient                                                                *client.RancherClient
	publicKeyFile, publicKeyFileContents, privateKeyFile, privateKeyFileContents string
)

//SetEnv sets the parameters necessary
func SetEnv(c *cli.Context) {

	publicKeyFile = c.GlobalString("rsa-public-key-file")
	publicKeyFileContents = c.GlobalString("rsa-public-key-contents")

	if publicKeyFile != "" && publicKeyFileContents != "" {
		log.Fatal("Can't specify both rsa-public-key-file and rsa-public-key-contents")
		return
	}

	if publicKeyFile != "" {
		publicKey = util.ParsePublicKey(publicKeyFile)
	} else if publicKeyFileContents != "" {
		publicKey = util.ParsePublicKeyContents(publicKeyFileContents)
	} else {
		log.Fatal("Please provide either rsa-public-key-file or rsa-public-key-contents, halting")
		return
	}

	privateKeyFile = c.GlobalString("rsa-private-key-file")
	privateKeyFileContents = c.GlobalString("rsa-private-key-contents")

	if privateKeyFile != "" && privateKeyFileContents != "" {
		log.Fatal("Can't specify both rsa-private-key-file and rsa-private-key-contents")
		return
	}

	if privateKeyFile != "" {
		privateKey = util.ParsePrivateKey(privateKeyFile)
	} else if privateKeyFileContents != "" {
		privateKey = util.ParsePrivateKeyContents(privateKeyFileContents)
	} else {
		log.Fatal("Please provide either rsa-private-key-file or rsa-private-key-contents, halting")
		return
	}

	cattleURL := c.GlobalString("cattle-url")
	if len(cattleURL) == 0 {
		log.Fatalf("CATTLE_URL is not set")
	}

	cattleAPIKey := c.GlobalString("cattle-access-key")
	if len(cattleAPIKey) == 0 {
		log.Fatalf("CATTLE_ACCESS_KEY is not set")
	}

	cattleSecretKey := c.GlobalString("cattle-secret-key")
	if len(cattleSecretKey) == 0 {
		log.Fatalf("CATTLE_SECRET_KEY is not set")
	}

	//configure cattle client
	var err error
	rancherClient, err = newCattleClient(cattleURL, cattleAPIKey, cattleSecretKey)
	if err != nil {
		log.Fatalf("Failed to configure cattle client: %v", err)
	}

	err = testCattleConnect()
	if err != nil {
		log.Errorf("Failed to connect to rancher cattle client: %v", err)
	}

	err = Reload()
	if err != nil {
		log.Fatalf("Failed to reload the auth config from db on start: %v", err)
	}
}

func newCattleClient(cattleURL string, cattleAccessKey string, cattleSecretKey string) (*client.RancherClient, error) {
	apiClient, err := client.NewRancherClient(&client.ClientOpts{
		Url:       cattleURL,
		AccessKey: cattleAccessKey,
		SecretKey: cattleSecretKey,
	})

	if err != nil {
		return nil, err
	}

	return apiClient, nil
}

func testCattleConnect() error {
	opts := &client.ListOpts{}
	_, err := rancherClient.ContainerEvent.List(opts)
	return err
}

func initProviderWithConfig(authConfig model.AuthConfig) (providers.IdentityProvider, error) {
	newProvider := providers.GetProvider(authConfig.Provider)
	if newProvider == nil {
		return nil, fmt.Errorf("Could not get the %s auth provider", authConfig.Provider)
	}
	err := newProvider.LoadConfig(authConfig)
	if err != nil {
		log.Debugf("Error Loading the provider config %v", err)
		return nil, err
	}
	return newProvider, nil
}

func readSettings(settings []string) (map[string]string, error) {
	var dbSettings = make(map[string]string)

	for _, key := range settings {
		setting, err := rancherClient.Setting.ById(key)
		if err != nil {
			log.Errorf("Error reading the setting %v , error: %v", key, err)
			return dbSettings, err
		}
		dbSettings[key] = setting.ActiveValue
	}

	return dbSettings, nil
}

func updateSettings(settings map[string]string) error {
	for key, value := range settings {
		if value != "" {
			log.Debugf("Update setting key:%v value: %v", key, value)
			setting, err := rancherClient.Setting.ById(key)
			if err != nil {
				log.Errorf("Error getting the setting %v , error: %v", key, err)
				return err
			}
			setting, err = rancherClient.Setting.Update(setting, &client.Setting{
				Value: value,
			})
			if err != nil {
				log.Errorf("Error updating the setting %v to value %v, error: %v", key, value, err)
				return err
			}
		}
	}
	return nil
}

func getAllowedIDString(allowedIdentities []client.Identity) string {
	if provider != nil {
		var idArray []string
		for _, identity := range allowedIdentities {
			idArray = append(idArray, identity.Id)
		}
		return strings.Join(idArray, ",")
	}
	return ""
}

func getAllowedIdentities(idString string, accessToken string) []client.Identity {
	var identities []client.Identity
	if idString != "" {
		externalIDList := strings.Split(idString, ",")
		for _, id := range externalIDList {
			var identity client.Identity
			var err error
			parts := strings.SplitN(id, ":", 2)

			if len(parts) < 2 {
				log.Debugf("Malformed Id, skipping this allowed identity %v", id)
				continue
			}

			if provider != nil && accessToken != "" {
				//get identities from the provider
				identity, err = provider.GetIdentity(parts[1], parts[0], accessToken)
				if err == nil {
					identities = append(identities, identity)
					continue
				}
			}

			identity = client.Identity{Resource: client.Resource{
				Type: "identity",
			}}
			identity.ExternalId = parts[1]
			identity.Resource.Id = id
			identity.ExternalIdType = parts[0]
			identities = append(identities, identity)
		}
	}

	return identities
}

//UpdateConfig updates the config in DB
func UpdateConfig(authConfig model.AuthConfig) error {
	newProvider, err := initProviderWithConfig(authConfig)
	if err != nil {
		log.Errorf("UpdateConfig: Cannot update the config, error initializing the provider %v", err)
		return err
	}
	//store the config to db
	providerSettings := newProvider.GetSettings()

	//add the generic settings
	providerSettings[accessModeSetting] = authConfig.AccessMode
	providerSettings[userTypeSetting] = newProvider.GetUserType()
	providerSettings[allowedIdentitiesSetting] = getAllowedIDString(authConfig.AllowedIdentities)
	providerSettings[securitySetting] = strconv.FormatBool(authConfig.Enabled)
	providerSettings[providerNameSetting] = authConfig.Provider
	providerSettings[providerSetting] = authConfig.Provider
	providerSettings[externalProviderSetting] = "true"
	err = updateSettings(providerSettings)
	if err != nil {
		log.Errorf("Error Storing the provider settings %v", err)
		return err
	}
	//switch the in-memory provider
	provider = newProvider
	authConfigInMemory = authConfig

	return nil
}

//GetConfig gets the config from DB, gathers the list of settings to read from DB
func GetConfig(accessToken string) (model.AuthConfig, error) {
	var config model.AuthConfig
	var settings []string

	config = model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	//add the generic settings
	settings = append(settings, accessModeSetting)
	settings = append(settings, allowedIdentitiesSetting)
	settings = append(settings, securitySetting)
	settings = append(settings, providerSetting)
	settings = append(settings, providerNameSetting)

	dbSettings, err := readSettings(settings)

	if err != nil {
		log.Errorf("GetConfig: Error reading DB settings %v", err)
		return config, err
	}

	config.AccessMode = dbSettings[accessModeSetting]
	config.AllowedIdentities = getAllowedIdentities(dbSettings[allowedIdentitiesSetting], accessToken)
	enabled, err := strconv.ParseBool(dbSettings[securitySetting])
	if err == nil {
		config.Enabled = enabled
	} else {
		config.Enabled = false
	}

	providerNameInDb := dbSettings[providerNameSetting]
	config.Provider = providerNameInDb
	//add the provider specific config
	newProvider := providers.GetProvider(config.Provider)
	if newProvider == nil {
		return config, fmt.Errorf("Could not get the %s auth provider", config.Provider)
	}
	providerSettings, err := readSettings(newProvider.GetProviderSettingList())
	newProvider.AddProviderConfig(&config, providerSettings)

	return config, nil
}

//Reload will reload the config from DB and reinit the provider
func Reload() error {
	//read config from db
	authConfig, err := GetConfig("")

	newProvider, err := initProviderWithConfig(authConfig)
	if err != nil {
		log.Errorf("Error initializing the provider %v", err)
		return err
	}
	provider = newProvider
	authConfigInMemory = authConfig
	return nil
}

//CreateToken will authenticate with provider and create a jwt token
func CreateToken(securityCode string) (model.Token, error) {
	if provider != nil {
		token, err := provider.GenerateToken(securityCode)
		if err != nil {
			return model.Token{}, err
		}

		payload := make(map[string]interface{})
		payload["access_token"] = token.AccessToken

		jwt, err := util.CreateTokenWithPayload(payload, privateKey)
		if err != nil {
			return model.Token{}, err
		}
		token.JwtToken = jwt

		return token, nil
	}
	return model.Token{}, fmt.Errorf("No auth provider configured")
}

//RefreshToken will refresh a jwt token
func RefreshToken(accessToken string) (model.Token, error) {
	if provider != nil {
		token, err := provider.RefreshToken(accessToken)
		if err != nil {
			return model.Token{}, err
		}

		payload := make(map[string]interface{})
		payload["access_token"] = token.AccessToken

		jwt, err := util.CreateTokenWithPayload(payload, privateKey)
		if err != nil {
			return model.Token{}, err
		}
		token.JwtToken = jwt

		return token, nil
	}
	return model.Token{}, fmt.Errorf("No auth provider configured")
}

func identitiesToIDList(identities []client.Identity) []string {
	var idList []string
	for _, identity := range identities {
		idList = append(idList, identity.Resource.Id)
	}
	return idList
}

//GetIdentities will list all identities for token
func GetIdentities(accessToken string) ([]client.Identity, error) {
	if provider != nil {
		return provider.GetIdentities(accessToken)
	}
	return []client.Identity{}, fmt.Errorf("No auth provider configured")
}

//GetIdentity will list all identities for given filters
func GetIdentity(externalID string, externalIDType string, accessToken string) (client.Identity, error) {
	if provider != nil {
		return provider.GetIdentity(externalID, externalIDType, accessToken)
	}
	return client.Identity{}, fmt.Errorf("No auth provider configured")
}

//SearchIdentities will list all identities for given filters
func SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	if provider != nil {
		return provider.SearchIdentities(name, exactMatch, accessToken)
	}
	return []client.Identity{}, fmt.Errorf("No auth provider configured")
}
