package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml/samlsp"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/rancher/go-rancher/v2"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers"
	"github.com/rancher/rancher-auth-service/util"
	"github.com/urfave/cli"
)

const (
	accessModeSetting                = "api.auth.access.mode"
	allowedIdentitiesSetting         = "api.auth.allowed.identities"
	userTypeSetting                  = "api.auth.user.type"
	providerSetting                  = "api.auth.provider.configured"
	providerNameSetting              = "api.auth.provider.name.configured"
	externalProviderSetting          = "api.auth.external.provider.configured"
	securitySetting                  = "api.security.enabled"
	apiHostSetting                   = "api.host"
	identitySeparatorSetting         = "api.auth.external.provider.identity.separator"
	authServiceLogSetting            = "auth.service.log.level"
	authServiceConfigUpdateTimestamp = "auth.service.config.update.timestamp"
)

var (
	provider           providers.IdentityProvider
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	authConfigInMemory model.AuthConfig
	//RancherClient is the client configured to connect to Cattle
	RancherClient                                                                *client.RancherClient
	publicKeyFile, publicKeyFileContents, privateKeyFile, privateKeyFileContents string
	selfSignedKeyFile, selfSignedCertFile                                        string
	//IDPMetadataFile is the path to the metadata file of the Shibboleth IDP
	IDPMetadataFile string
	//SamlServiceProvider is the handle to the SamlServiceProvider configured by the router
	SamlServiceProvider *samlsp.Middleware
	refreshReqChannel   *chan int
	authConfigFile      string
	key                 []byte
)

type AESSecret struct {
	Nonce      []byte
	CipherText []byte
}

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

	selfSignedKeyFile = c.GlobalString("self-signed-key-file")
	selfSignedCertFile = c.GlobalString("self-signed-cert-file")
	IDPMetadataFile = c.GlobalString("idp-metadata-file")
	authConfigFile = c.GlobalString("auth-config-file")

	//configure cattle client
	var err error
	RancherClient, err = newCattleClient(cattleURL, cattleAPIKey, cattleSecretKey)
	if err != nil {
		log.Fatalf("Failed to configure cattle client: %v", err)
	}

	err = testCattleConnect()
	if err != nil {
		log.Errorf("Failed to connect to rancher cattle client: %v", err)
	}

	err = UpgradeSettings()
	if err != nil {
		log.Fatalf("Failed to upgrade the existing auth settings in db to new: %v", err)
	}

	key, err = readPrivateKey()
	if err != nil {
		log.Fatalf("Failed to read key with error: %v", err)
	}

	refChan := make(chan int, 1)
	refreshReqChannel = &refChan
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
	_, err := RancherClient.ContainerEvent.List(opts)
	return err
}

func initProviderWithConfig(authConfig *model.AuthConfig) (providers.IdentityProvider, error) {
	newProvider, err := providers.GetProvider(authConfig.Provider)
	if err != nil {
		return nil, err
	}
	if newProvider == nil {
		return nil, fmt.Errorf("Could not get the %s auth provider", authConfig.Provider)
	}
	err = newProvider.LoadConfig(authConfig)
	if err != nil {
		log.Debugf("Error Loading the provider config %v", err)
		return nil, err
	}
	return newProvider, nil
}

// This code is adapted from rancher secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/key.go#L36
func readPrivateKey() ([]byte, error) {
	keyData, err := ioutil.ReadFile(authConfigFile)
	if err != nil {
		log.Errorf("Returning error, authConfigFile %s not found", authConfigFile)
		return []byte{}, err
	}

	log.Debug("Key: %s", string(keyData))
	return keyData, nil
}

// InitBlock adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L34
func initBlock() (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if block == nil {
		return nil, fmt.Errorf("Uninitialized Cipher Block")
	}

	return block, nil
}

// GetEncryptedText adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L53
func encryptConfig(key []byte, clearText []byte) (string, error) {
	secret := &AESSecret{}
	cipherBlock, err := initBlock()
	if err != nil {
		return "", err
	}

	nonce, err := randomNonce(12)
	if err != nil {
		return "", err
	}

	secret.Nonce = nonce

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	secret.CipherText = gcm.Seal(nil, secret.Nonce, clearText, nil)

	jsonSecret, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}

	return string(jsonSecret), nil
}

// GetClearText adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L86
func decryptConfig(key []byte, secretBlob string) ([]byte, error) {
	secret := &AESSecret{}

	err := json.Unmarshal([]byte(secretBlob), secret)
	if err != nil {
		return []byte{}, err
	}

	cipherBlock, err := initBlock()
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return []byte{}, err
	}

	plainText, err := gcm.Open(nil, secret.Nonce, secret.CipherText, nil)
	if err != nil {
		return []byte{}, err
	}

	return plainText, nil
}

// adapted from secrets-api https://github.com/rancher/secrets-api/blob/master/pkg/aesutils/aesgcm.go#L112
func randomNonce(byteLength int) ([]byte, error) {
	key := make([]byte, byteLength)

	_, err := rand.Read(key)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}

func readSettings(provider string) (map[string]string, error) {
	var dbSettings = make(map[string]map[string]string)
	var nilSettings = make(map[string]string)
	filters := make(map[string]interface{})
	filters["key"] = "auth.config"
	authColl, err := RancherClient.GenericObject.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		log.Errorf("Error getting the go %v , error: %v", key, err)
		return nil, err
	}

	if len(authColl.Data) == 0 {
		log.Info("No config stored")
		return nilSettings, nil
	}

	authConfigRes := authColl.Data[0]
	authConfig := authConfigRes.ResourceData["data"]
	byteSettings, err := decryptConfig(key, authConfig.(string))
	err = json.Unmarshal(byteSettings, &dbSettings)
	if err != nil {
		return nilSettings, err
	}
	log.Debugf("Settings from db for provider %s: %v", provider, dbSettings)
	return dbSettings[provider], nil
}

func readCommonSettings(settings []string) (map[string]string, error) {
	var dbSettings = make(map[string]string)

	for _, key := range settings {
		setting, err := RancherClient.Setting.ById(key)
		if err != nil {
			log.Errorf("Error reading the setting %v , error: %v", key, err)
			return dbSettings, err
		}
		dbSettings[key] = setting.ActiveValue
	}

	return dbSettings, nil
}

func updateSettings(saveConfig map[string]map[string]string, secretSettings []string, providerName string) error {
	log.Debugf("Updated auth config: %#v", saveConfig)
	clearText, err := json.Marshal(saveConfig)
	if err != nil {
		return err
	}

	encrConf, err := encryptConfig(key, clearText)
	if err != nil {
		return err
	}

	resourceData := map[string]interface{}{
		"data": encrConf,
	}
	// Save entire encryped conf in GO
	filters := make(map[string]interface{})
	filters["key"] = "auth.config"
	authColl, err := RancherClient.GenericObject.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		log.Errorf("Error getting the go %v , error: %v", key, err)
		return err
	}

	if len(authColl.Data) == 0 {
		_, err := RancherClient.GenericObject.Create(&client.GenericObject{
			Name:         "auth.config",
			Key:          "auth.config",
			ResourceData: resourceData,
			Kind:         "authConfig",
		})
		if err != nil {
			log.Errorf("Error creating the go, error: %v", err)
			return err
		}
	} else {
		// Get the previously saved data, decrypt and append
		authConfig := make(map[string]map[string]string)
		prevConfig := authColl.Data[0].ResourceData["data"]
		byteSettings, err := decryptConfig(key, prevConfig.(string))
		err = json.Unmarshal(byteSettings, &authConfig)
		if err != nil {
			return err
		}

		// authConfig now was prevConfig
		// saveConfig is to be saved, so authConfig should get added values from saveConfig
		log.Debugf("Previous saved auth config: %v", authConfig)
		// If saveConfig (updated config) does not have secret settings, but authConfig(previous config does), restore the secret settings
		prevProviderSettings, prevProviderPresent := authConfig[providerName]
		updatedProviderSettings, updatedProviderPresent := saveConfig[providerName]
		if prevProviderPresent && updatedProviderPresent {
			for _, s := range secretSettings {
				_, prevPresent := prevProviderSettings[s]
				_, updatedPresent := updatedProviderSettings[s]
				if prevPresent && !updatedPresent {
					saveConfig[providerName][s] = authConfig[providerName][s]
				}
			}
		}

		for key, val := range saveConfig {
			authConfig[key] = val
		}
		log.Debugf("Updated auth config: %v", authConfig)
		clearText, err := json.Marshal(authConfig)
		if err != nil {
			return err
		}

		encrConf, err := encryptConfig(key, clearText)
		if err != nil {
			return err
		}

		resourceData := map[string]interface{}{
			"data": encrConf,
		}
		_, err = RancherClient.GenericObject.Update(&authColl.Data[0], &client.GenericObject{
			ResourceData: resourceData,
		})
		if err != nil {
			log.Errorf("Error updating the go, error: %v", err)
			return err
		}
	}
	return nil
}

func updateCommonSettings(settings map[string]string) error {
	for key, value := range settings {
		if value != "" {
			log.Debugf("Update setting key:%v value: %v", key, value)
			setting, err := RancherClient.Setting.ById(key)
			if err != nil {
				log.Errorf("Error getting the setting %v , error: %v", key, err)
				return err
			}

			setting, err = RancherClient.Setting.Update(setting, &client.Setting{
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

func getAllowedIdentities(idString string, accessToken string, separator string) []client.Identity {
	var identities []client.Identity
	if idString != "" {
		externalIDList := strings.Split(idString, separator)
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
	if authConfig.Provider == "shibbolethconfig" {
		authConfig.ShibbolethConfig.IDPMetadataFilePath = IDPMetadataFile
		authConfig.ShibbolethConfig.SPSelfSignedCertFilePath = selfSignedCertFile
		authConfig.ShibbolethConfig.SPSelfSignedKeyFilePath = selfSignedKeyFile
		authConfig.ShibbolethConfig.RancherAPIHost = GetRancherAPIHost()
	}

	newProvider, err := initProviderWithConfig(&authConfig)
	if err != nil {
		log.Errorf("UpdateConfig: Cannot update the config, error initializing the provider %v", err)
		return err
	}
	//store the config to db
	log.Infof("newProvider %v", newProvider.GetName())

	providerSettings := newProvider.GetSettings()

	genObjConfig := make(map[string]map[string]string)
	genObjConfig[newProvider.GetName()] = providerSettings
	err = updateSettings(genObjConfig, newProvider.GetProviderSecretSettings(), newProvider.GetName())
	if err != nil {
		log.Errorf("UpdateConfig: Error Storing the provider settings %v", err)
		return err
	}

	//add the generic settings
	commonSettings := make(map[string]string)
	commonSettings[accessModeSetting] = authConfig.AccessMode
	commonSettings[userTypeSetting] = newProvider.GetUserType()
	commonSettings[identitySeparatorSetting] = newProvider.GetIdentitySeparator()
	commonSettings[allowedIdentitiesSetting] = getAllowedIDString(authConfig.AllowedIdentities, newProvider.GetIdentitySeparator())
	commonSettings[providerNameSetting] = authConfig.Provider
	commonSettings[providerSetting] = authConfig.Provider
	commonSettings[externalProviderSetting] = "true"
	commonSettings[authServiceConfigUpdateTimestamp] = time.Now().String()
	err = updateCommonSettings(commonSettings)
	if err != nil {
		return errors.Wrap(err, "UpdateConfig: Error Storing the common settings")
	}

	//set the security setting last specifically
	commonSettings = make(map[string]string)
	commonSettings[securitySetting] = strconv.FormatBool(authConfig.Enabled)
	err = updateCommonSettings(commonSettings)
	if err != nil {
		return errors.Wrap(err, "UpdateConfig: Error Storing the provider securitySetting")
	}

	//switch the in-memory provider
	if provider == nil {
		if authConfig.Provider == "shibbolethconfig" {
			SamlServiceProvider = authConfig.ShibbolethConfig.SamlServiceProvider
		}
		provider = newProvider
		authConfigInMemory = authConfig
	} else {
		//reload the in-memory provider
		log.Infof("Calling reload")
		err = Reload()
		if err != nil {
			log.Errorf("Failed to reload the auth provider from db on updateConfig: %v", err)
			return err
		}
	}

	return nil
}

//UpgradeSettings upgrades the existing provider specific auth settings to the new generic settings used by this service
func UpgradeSettings() error {
	//read the current provider
	var settings []string
	settings = append(settings, providerSetting)
	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		log.Errorf("UpgradeSettings: Error reading existing DB settings %v", err)
		return err
	}

	providerNameInDb := dbSettings[providerSetting]
	if providerNameInDb != "" {
		if providers.IsProviderSupported(providerNameInDb) {
			//upgrade to new settings and set external provider as true
			newProvider, err := providers.GetProvider(providerNameInDb)
			if err != nil {
				return err
			}
			if newProvider == nil {
				return fmt.Errorf("UpgradeSettings: Cannot upgrade the setup, could not get the %s auth provider", providerNameInDb)
			}

			legacySettingsMap := newProvider.GetLegacySettings()
			var legacySettings []string
			legacySettings = append(legacySettings, legacySettingsMap["accessModeSetting"])
			legacySettings = append(legacySettings, legacySettingsMap["allowedIdentitiesSetting"])

			dbLegacySettings, err := readCommonSettings(legacySettings)
			if err != nil {
				log.Errorf("UpgradeSettings: Error reading existing DB legacy settings %v", err)
				return err
			}

			//add the new settings
			commonSettings := map[string]string{}
			commonSettings[accessModeSetting] = dbLegacySettings[legacySettingsMap["accessModeSetting"]]
			commonSettings[userTypeSetting] = newProvider.GetUserType()
			commonSettings[identitySeparatorSetting] = newProvider.GetIdentitySeparator()
			commonSettings[allowedIdentitiesSetting] = dbLegacySettings[legacySettingsMap["allowedIdentitiesSetting"]]
			commonSettings[providerNameSetting] = providerNameInDb
			commonSettings[externalProviderSetting] = "true"

			err = updateCommonSettings(commonSettings)
			if err != nil {
				log.Errorf("UpgradeSettings: Error Storing the new external provider settings %v", err)
				return err
			}
		}
	}
	return nil
}

func UpgradeCase() error {
	var settings []string
	genObjConfig := make(map[string]map[string]string)
	config := model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	// check if GenericObject with key="auth.config" exists
	filters := make(map[string]interface{})
	filters["key"] = "auth.config"
	authColl, err := RancherClient.GenericObject.List(&client.ListOpts{
		Filters: filters,
	})
	if err != nil {
		log.Errorf("Error getting the go 'auth.config', error: %v", err)
		return err
	}

	if len(authColl.Data) > 0 {
		log.Info("Config stored")
		return nil
	}

	//add the common settings
	settings = append(settings, accessModeSetting)
	settings = append(settings, allowedIdentitiesSetting)
	settings = append(settings, securitySetting)
	settings = append(settings, providerSetting)
	settings = append(settings, providerNameSetting)

	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		return errors.Wrap(err, "UpgradeCase: Error reading DB settings")
	}

	// Get all provider specific settings from setting table for previously configured auth control
	for _, val := range providers.Providers {
		p, err := providers.GetProvider(val)
		if err != nil {
			return err
		}
		if p == nil {
			return errors.Wrapf(err, "UpgradeCase: Could not get the %s auth provider", val)
		}
		pSettings, err := readCommonSettings(p.GetProviderSettingList(false))
		if err != nil {
			return errors.Wrap(err, "UpgradeCase: Error reading DB settings for previous auth providers")
		}
		genObjConfig[p.GetName()] = pSettings
	}

	config.AccessMode = dbSettings[accessModeSetting]
	enabled, err := strconv.ParseBool(dbSettings[securitySetting])
	if err == nil {
		config.Enabled = enabled
	} else {
		config.Enabled = false
	}

	if enabled {
		// GO doesn't exist, so first load the config struct, then get providerSettings for enabled provider
		providerNameInDb := dbSettings[providerNameSetting]
		if !providers.IsProviderSupported(providerNameInDb) {
			log.Debug("Auth provider not supported by rancher-auth-service")
			return nil
		}
		config.Provider = providerNameInDb
		newProvider, err := providers.GetProvider(providerNameInDb)
		if err != nil {
			return err
		}

		if newProvider == nil {
			return errors.Wrapf(err, "UpgradeCase: Could not get the %s auth provider", config.Provider)
		}

		config.AllowedIdentities = getAllowedIdentities(dbSettings[allowedIdentitiesSetting], "", newProvider.GetIdentitySeparator())
		providerSettings, err := readCommonSettings(newProvider.GetProviderSettingList(false))
		if err != nil {
			return errors.Wrap(err, "UpgradeCase: Error reading provider DB settings")
		}
		newProvider.AddProviderConfig(&config, providerSettings)

		provider, err = initProviderWithConfig(&config)
		if err != nil {
			return errors.Wrap(err, "UpgradeCase: Cannot update the config, error initializing the provider")
		}

		providerSettings = provider.GetSettings()
		genObjConfig[provider.GetName()] = providerSettings
		return updateSettings(genObjConfig, provider.GetProviderSecretSettings(), provider.GetName())
	}
	return nil
}

//GetConfig gets the config from DB, gathers the list of settings to read from DB
func GetConfig(accessToken string, listOnly bool) (model.AuthConfig, error) {
	var config model.AuthConfig
	var settings []string
	var allowedSettings = make(map[string]bool)
	var secretSettings []string

	config = model.AuthConfig{Resource: client.Resource{
		Type: "config",
	}}

	//add the generic settings
	settings = append(settings, accessModeSetting)
	settings = append(settings, allowedIdentitiesSetting)
	settings = append(settings, securitySetting)
	settings = append(settings, providerSetting)
	settings = append(settings, providerNameSetting)
	settings = append(settings, authServiceLogSetting)

	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		log.Errorf("GetConfig: Error reading DB settings %v", err)
		return config, err
	}

	if dbSettings[authServiceLogSetting] != "" {
		switch strings.ToLower(dbSettings[authServiceLogSetting]) {
		case "trace":
			log.SetLevel(log.DebugLevel)
		case "debug":
			log.SetLevel(log.DebugLevel)
		case "info":
			log.SetLevel(log.InfoLevel)
		case "warn":
			log.SetLevel(log.WarnLevel)
		case "error":
			log.SetLevel(log.ErrorLevel)
		case "fatal":
			log.SetLevel(log.FatalLevel)
		case "panic":
			log.SetLevel(log.PanicLevel)
		}
	}

	config.AccessMode = dbSettings[accessModeSetting]

	enabled, err := strconv.ParseBool(dbSettings[securitySetting])
	if err == nil {
		config.Enabled = enabled
	} else {
		config.Enabled = false
	}

	providerNameInDb := dbSettings[providerNameSetting]

	if providerNameInDb != "" {
		if providers.IsProviderSupported(providerNameInDb) {
			config.Provider = providerNameInDb
			//add the provider specific config
			newProvider, err := providers.GetProvider(config.Provider)
			if err != nil {
				return config, err
			}
			if newProvider == nil {
				log.Errorf("GetConfig: Could not get the %s auth provider", config.Provider)
				return config, nil
			}
			config.AllowedIdentities = getAllowedIdentities(dbSettings[allowedIdentitiesSetting], accessToken, newProvider.GetIdentitySeparator())
			settingNames := newProvider.GetProviderSettingList(listOnly)
			providerSettings, err := readSettings(newProvider.GetName())
			// Filter out provider specific secret settings if listOnly=true
			if listOnly {
				for _, s := range settingNames {
					allowedSettings[s] = true
				}
				for k := range providerSettings {
					if !allowedSettings[k] {
						secretSettings = append(secretSettings, k)
					}
				}
				for _, k := range secretSettings {
					delete(providerSettings, k)
				}
			}
			log.Debugf("Provider settings: %v", providerSettings)
			if err != nil {
				log.Errorf("GetConfig: Error reading provider DB settings %v", err)
				return config, nil
			}
			newProvider.AddProviderConfig(&config, providerSettings)
		}
	} else {
		config.Provider = dbSettings[providerSetting]
	}
	return config, nil
}

//Reload will reload the config from DB and reinit the provider
func Reload() error {
	//put msg on channel, so that any other request can wait
	select {
	case *refreshReqChannel <- 1:
		//read config from db
		authConfig, err := GetConfig("", false)

		//check if the auth is enabled, if yes then load the provider.
		if authConfig.Provider == "" {
			log.Info("No Auth provider configured")
			<-*refreshReqChannel
			return nil
		}
		if !providers.IsProviderSupported(authConfig.Provider) {
			log.Debug("Auth provider not supported by rancher-auth-service")
			<-*refreshReqChannel
			return nil
		}

		if authConfig.Provider == "shibbolethconfig" {
			authConfig.ShibbolethConfig.IDPMetadataFilePath = IDPMetadataFile
			authConfig.ShibbolethConfig.SPSelfSignedCertFilePath = selfSignedCertFile
			authConfig.ShibbolethConfig.SPSelfSignedKeyFilePath = selfSignedKeyFile
			authConfig.ShibbolethConfig.RancherAPIHost = GetRancherAPIHost()
		}

		log.Infof(" Auth provider configured %v", authConfig.Provider)

		newProvider, err := initProviderWithConfig(&authConfig)
		if err != nil {
			log.Errorf("Error initializing the provider %v", err)
			<-*refreshReqChannel
			return err
		}
		if authConfig.Provider == "shibbolethconfig" {
			SamlServiceProvider = authConfig.ShibbolethConfig.SamlServiceProvider
		}
		provider = newProvider
		authConfigInMemory = authConfig
		<-*refreshReqChannel
	default:
		log.Infof("Reload config is already in process, skipping")
	}
	return nil
}

//CreateToken will authenticate with provider and create a jwt token
func CreateToken(json map[string]string) (model.Token, int, error) {
	if provider != nil {
		token, status, err := provider.GenerateToken(json)
		if err != nil {
			return model.Token{}, status, err
		}

		payload := make(map[string]interface{})
		payload["access_token"] = token.AccessToken

		jwt, err := util.CreateTokenWithPayload(payload, privateKey)
		if err != nil {
			return model.Token{}, 0, err
		}
		token.JwtToken = jwt

		return token, 0, nil
	}
	return model.Token{}, 0, fmt.Errorf("No auth provider configured")
}

//RefreshToken will refresh a jwt token
func RefreshToken(json map[string]string) (model.Token, int, error) {
	if provider != nil {
		token, status, err := provider.RefreshToken(json)
		if err != nil {
			return model.Token{}, status, err
		}

		payload := make(map[string]interface{})
		payload["access_token"] = token.AccessToken

		jwt, err := util.CreateTokenWithPayload(payload, privateKey)
		if err != nil {
			return model.Token{}, 0, err
		}
		token.JwtToken = jwt
		return token, 0, nil
	}
	return model.Token{}, 0, fmt.Errorf("No auth provider configured")
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

//GetSamlAuthToken handles the SAML assertions posted by an IDP
func GetSamlAuthToken(samlData map[string][]string) (string, error) {
	//ensure SAML provider is enabled
	if provider != nil && provider.GetName() == "shibboleth" {
		rancherAPI := GetRancherAPIHost()
		//get the SAML data, create a jwt token and POST to /v1/token with code = "jwt token"
		mapB, _ := json.Marshal(samlData)
		log.Debugf("GetSamlAuthToken : samlData %v ", string(mapB))

		inputJSON := make(map[string]string)
		inputJSON["code"] = string(mapB)
		outputJSON := make(map[string]interface{})

		tokenURL := rancherAPI + "/v1/token"
		log.Debugf("GetSamlAuthToken: tokenURL %v ", tokenURL)

		err := RancherClient.Post(tokenURL, inputJSON, &outputJSON)
		if err != nil {
			log.Errorf("HandleSAMLPost: Error doing POST /v1/token: %v, data: %v", err, samlData)
			return "", err
		}

		jwt := outputJSON["jwt"].(string)
		log.Debugf("GetSamlAuthToken: Got token %v ", jwt)

		return jwt, nil
	}
	return "", nil
}

//GetRancherAPIHost reads the api.host setting
func GetRancherAPIHost() string {
	var settings []string

	//add the setting
	settings = append(settings, apiHostSetting)
	dbSettings, err := readCommonSettings(settings)
	if err != nil {
		log.Errorf("getRancherAPIHost: Error reading DB setting %v", err)
		return "http://localhost:8080"
	}
	apiHost := dbSettings[apiHostSetting]
	if apiHost == "" {
		apiHost = "http://localhost:8080"
	}

	log.Debugf("getRancherAPIHost() returning %v ", apiHost)

	return apiHost
}

//GetRedirectURL returns the redirect URL for the provider if applicable
func GetRedirectURL() (map[string]string, error) {
	response := make(map[string]string)
	if provider != nil {
		redirect := provider.GetRedirectURL()
		response["redirectUrl"] = URLEncoded(redirect)
		response["provider"] = provider.GetName()
		log.Debugf("GetRedirectURL: returning response %v", response)
		return response, nil
	}
	return response, fmt.Errorf("No auth provider configured")
}

//URLEncoded escape url query
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		log.Errorf("Error encoding the url: %s , error: %v", str, err)
		return str
	}

	u.RawQuery = u.Query().Encode()
	return u.String()
}

//GetSamlRedirectURL returns the redirect URL for SAML login flow
func GetSamlRedirectURL(redirectBackBase string, redirectBackPath string) string {
	redirectURL := ""
	if provider != nil && provider.GetName() == "shibboleth" {
		rancherAPI := GetRancherAPIHost()
		redirectURL = redirectBackBase + redirectBackPath
		if redirectURL == "" {
			//default to api.host setting
			redirectURL = rancherAPI + redirectBackPath
		}
		log.Debugf("GetSamlRedirectURL : redirectURL %v ", redirectURL)
	}
	return redirectURL
}

//IsSamlJWTValid verfies the saml JWT token
func IsSamlJWTValid(value string) (bool, map[string][]string) {
	samlData := make(map[string][]string)
	if provider != nil && provider.GetName() == "shibboleth" {
		if SamlServiceProvider != nil {
			token, err := jwt.Parse(value, func(t *jwt.Token) (interface{}, error) {
				secretBlock, _ := pem.Decode([]byte(SamlServiceProvider.ServiceProvider.Key))
				return secretBlock.Bytes, nil
			})
			if err != nil || !token.Valid {
				log.Infof("IsSamlJWTValid: invalid token: %s", err)
				return false, samlData
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				for key, values := range claims {
					if key == "exp" {
						continue
					}
					valueSlice := values.([]interface{})
					valueStrs := make([]string, len(valueSlice))
					for i, value := range valueSlice {
						valueStrs[i] = value.(string)
					}
					samlData[key] = valueStrs
				}
			} else {
				log.Infof("IsSamlJWTValid: claims not found in token")
				return false, samlData
			}
			return true, samlData
		}
	}
	return false, samlData
}

func TestLogin(testAuthConfig model.TestAuthConfig) (int, error) {
	authConfig := testAuthConfig.AuthConfig
	newProvider, err := initProviderWithConfig(&authConfig)
	if err != nil {
		log.Errorf("GetProvider: Error initializing the provider %v", err)
		return 0, err
	}

	log.Infof("newProvider %v", newProvider.GetName())
	status, err := newProvider.TestLogin(&testAuthConfig)
	if err != nil {
		log.Errorf("GetProvider: Error in login %v", err)
		return status, err
	}
	return 0, nil
}
