package github

import (
	"fmt"
	"github.com/rancher/go-rancher/client"
	"strconv"
)

type GithubAccount struct {
	Id        int    `json:"id,omitempty"`
	Login     string `json:"login,omitempty"`
	Name      string `json:"name,omitempty"`
	AvatarUrl string `json:"avatar_url,omitempty"`
	HtmlUrl   string `json:"html_url,omitempty"`
}

func (a *GithubAccount) toIdentity(externalIdType string, identity *client.Identity) {
	identity.ExternalId = strconv.Itoa(a.Id)
	identity.Resource.Id = externalIdType + ":" + strconv.Itoa(a.Id)
	identity.ExternalIdType = externalIdType
	if a.Name != "" {
		identity.Name = a.Name
	} else {
		identity.Name = a.Login
	}
	identity.Login = a.Login
	identity.ProfilePicture = a.AvatarUrl
	identity.ProfileUrl = a.HtmlUrl
}

type GithubTeam struct {
	Id           int                    `json:"id,omitempty"`
	Organization map[string]interface{} `json:"organization,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Slug         string                 `json:"slug,omitempty"`
}

func (t *GithubTeam) toGithubAccount(url string, account *GithubAccount) {
	account.Id = t.Id
	account.Name = t.Name
	orgLogin := (t.Organization["login"]).(string)
	account.AvatarUrl = t.Organization["avatar_url"].(string)
	account.HtmlUrl = fmt.Sprintf(url, orgLogin, t.Slug)
	account.Login = t.Slug
}
