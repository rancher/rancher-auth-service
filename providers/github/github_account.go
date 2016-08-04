package github

import (
	"fmt"
	"github.com/rancher/go-rancher/client"
	"strconv"
)

//Account defines properties an account on github has
type Account struct {
	ID        int    `json:"id,omitempty"`
	Login     string `json:"login,omitempty"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	HTMLURL   string `json:"html_url,omitempty"`
}

func (a *Account) toIdentity(externalIDType string, identity *client.Identity) {
	identity.ExternalId = strconv.Itoa(a.ID)
	identity.Resource.Id = externalIDType + ":" + strconv.Itoa(a.ID)
	identity.ExternalIdType = externalIDType
	if a.Name != "" {
		identity.Name = a.Name
	} else {
		identity.Name = a.Login
	}
	identity.Login = a.Login
	identity.ProfilePicture = a.AvatarURL
	identity.ProfileUrl = a.HTMLURL
}

//Team defines properties a team on github has
type Team struct {
	ID           int                    `json:"id,omitempty"`
	Organization map[string]interface{} `json:"organization,omitempty"`
	Name         string                 `json:"name,omitempty"`
	Slug         string                 `json:"slug,omitempty"`
}

func (t *Team) toGithubAccount(url string, account *Account) {
	account.ID = t.ID
	account.Name = t.Name
	orgLogin := (t.Organization["login"]).(string)
	account.AvatarURL = t.Organization["avatar_url"].(string)
	account.HTMLURL = fmt.Sprintf(url, orgLogin, t.Slug)
	account.Login = t.Slug
}
