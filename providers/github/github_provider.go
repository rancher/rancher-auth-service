package github

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/rancher-auth-service/model"
	"github.com/rancher/rancher-auth-service/providers"
	"io/ioutil"
	"net/http"
)

const (
	Name      = "github"
	TokenType = Name + "jwt"
	UserType  = Name + "_user"
	OrgType   = Name + "_org"
	TeamType  = Name + "_team"
)

func init() {
	client := &http.Client{}
	githubClient := &GithubClient{}
	githubClient.httpClient = client

	githubProvider := &GitHubIdentityProvider{}
	githubProvider.githubClient = githubClient

	if err := providers.RegisterProvider(Name, githubProvider); err != nil {
		log.Fatalf("Could not register %s provider", Name)
	}

	log.Infof("Configured %s Auth provider", githubProvider.GetName())

}

type GitHubIdentityProvider struct {
	githubClient *GithubClient
}

func (g *GitHubIdentityProvider) GetName() string {
	return Name
}

func (g *GitHubIdentityProvider) GenerateToken(securityCode string) (model.Token, error) {
	//getAccessToken
	log.Debugf("GitHubIdentityProvider GenerateToken called for securityCode %v", securityCode)
	accessToken, err := g.githubClient.getAccessToken(securityCode)
	if err != nil {
		log.Errorf("Error generating accessToken from github %v", err)
		return model.Token{}, err
	}
	log.Debugf("Received AccessToken from github %v", accessToken)
	return g.createToken(accessToken)
}

func (g *GitHubIdentityProvider) createToken(accessToken string) (model.Token, error) {
	var token model.Token
	token.AccessToken = accessToken
	//getIdentities from accessToken
	identities, err := g.GetIdentities(accessToken)
	if err != nil {
		log.Errorf("Error getting identities using accessToken from github %v", err)
		return model.Token{}, err
	}
	token.IdentityList = identities
	token.Type = TokenType
	user, ok := providers.GetUserIdentity(identities, UserType)
	if !ok {
		log.Error("User identity not found using accessToken from github")
		return model.Token{}, fmt.Errorf("User identity not found using accessToken from github")
	}
	token.ExternalAccountId = user.ExternalId
	return token, nil
}

func (g *GitHubIdentityProvider) RefreshToken(accessToken string) (model.Token, error) {
	log.Debugf("GitHubIdentityProvider RefreshToken called for accessToken %v", accessToken)
	return g.createToken(accessToken)
}

func (g *GitHubIdentityProvider) GetIdentities(accessToken string) ([]client.Identity, error) {
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

func (g *GitHubIdentityProvider) GetIdentity(externalId string, externalIdType string, accessToken string) (client.Identity, error) {
	identity := client.Identity{Resource: client.Resource{
		Type: "identity",
	}}

	switch externalIdType {
	case UserType:
		fallthrough
	case OrgType:
		githubAcct, err := g.githubClient.getUserOrgById(externalId, accessToken)
		if err != nil {
			return identity, err
		}
		githubAcct.toIdentity(externalIdType, &identity)
		return identity, nil
	case TeamType:
		githubAcct, err := g.githubClient.getTeamById(externalId, accessToken)
		if err != nil {
			return identity, err
		}
		githubAcct.toIdentity(externalIdType, &identity)
		return identity, nil
	default:
		log.Debugf("Cannot get the github account due to invalid ExternalIdType %v", externalIdType)
		return identity, fmt.Errorf("Cannot get the github account due to invalid ExternalIdType %v", externalIdType)
	}
}

func (g *GitHubIdentityProvider) SearchIdentities(name string, exactMatch bool, accessToken string) ([]client.Identity, error) {
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

func (g *GitHubIdentityProvider) LoadConfig(configFilePath string) error {
	//generate githubConfig
	var configObj GithubConfig

	configContent, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		log.Debugf("JSON Config file does not exist")
		return err
	}
	err = json.Unmarshal(configContent, &configObj)
	if err != nil {
		log.Errorf("JSON config data format invalid, error : %v\n", err)
		return err
	}
	g.githubClient.config = &configObj

	return nil
}
