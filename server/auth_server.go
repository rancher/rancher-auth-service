package server

import (
	"crypto/rsa"
	"flag"
	log "github.com/Sirupsen/logrus"

	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/providers"
	_ "github.com/rancher/rancher-auth-service/providers/github"
	"github.com/rancher/rancher-auth-service/util"
)

var (
	provider       providers.IdentityProvider
	PrivateKey     *rsa.PrivateKey
	PublicKey      *rsa.PublicKey
	providerName   = flag.String("provider", "", "External provider name")
	debug          = flag.Bool("debug", false, "Debug")
	logFile        = flag.String("log", "", "Log file")
	configFilePath = flag.String("configFile", "", "Path of the Config file")
	publicKeyFile  = flag.String("publicKeyFile", "", "Path of file containing RSA Public key")
	privateKeyFile = flag.String("privateKeyFile", "", "Path of file containing RSA Private key")
)

func SetEnv() {
	flag.Parse()

	textFormatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(textFormatter)

	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	if *providerName == "" {
		log.Fatal("Please provide the auth provider '-provider', Cannot initialize auth server, halting")
		return
	}

	if *configFilePath == "" {
		log.Fatalf("Please provide the config file for initializing the %s auth provider, halting", *providerName)
		return
	}

	if *publicKeyFile == "" {
		log.Fatal("Please provide the RSA public key, halting")
		return
	}
	PublicKey = util.ParsePublicKey(*publicKeyFile)

	if *privateKeyFile == "" {
		log.Fatal("Please provide the RSA private key, halting")
		return
	}
	PrivateKey = util.ParsePrivateKey(*privateKeyFile)

	provider = providers.GetProvider(*providerName)
	if provider == nil {
		log.Fatalf("Could not get the %s auth provider, halting", *providerName)
	}

	provider.LoadConfig(*configFilePath)

}

/*func GetToken(securityCode string) (model.Token, error) {
	return provider.GenerateToken(securityCode)
}*/

func GetToken(securityCode string) (string, error) {
	token, err := provider.GenerateToken(securityCode)
	if err != nil {
		return "", err
	}

	payload := make(map[string]interface{})
	payload["token"] = token.Type
	payload["account_id"] = token.ExternalAccountId
	payload["access_token"] = token.AccessToken
	payload["idList"] = identitiesToIdList(token.IdentityList)
	payload["identities"] = token.IdentityList

	return util.CreateTokenWithPayload(payload, PrivateKey)
}

func RefreshToken(accessToken string) (string, error) {
	token, err := provider.RefreshToken(accessToken)
	if err != nil {
		return "", err
	}

	payload := make(map[string]interface{})
	payload["token"] = token.Type
	payload["account_id"] = token.ExternalAccountId
	payload["access_token"] = token.AccessToken
	payload["idList"] = identitiesToIdList(token.IdentityList)
	payload["identities"] = token.IdentityList

	return util.CreateTokenWithPayload(payload, PrivateKey)
}

func identitiesToIdList(identities []client.Identity) []string {
	var idList []string
	for _, identity := range identities {
		idList = append(idList, identity.Resource.Id)
	}
	return idList
}

func GetIdentities(accessToken string) ([]client.Identity, error) {
	return provider.GetIdentities(accessToken)
}

func GetIdentity(externalId string, externalIdType string, accessToken string) (client.Identity, error) {
	return provider.GetIdentity(externalId, externalIdType, accessToken)
}

func SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
	return provider.SearchIdentities(name, exactMatch, accessToken)
}
