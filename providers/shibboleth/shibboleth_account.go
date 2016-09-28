package shibboleth

import (
	//"fmt"
	"github.com/rancher/go-rancher/client"
	//"strconv"
)

//Account defines properties an account details shibboleth IDP provides. Account can also be created for a group entity.
type Account struct {
	UID         string `json:"uid,omitempty"`         //objectId
	DisplayName string `json:"displayname,omitempty"` //name
	UserName    string `json:"username,omitempty"`    //samAccountName (login name)
	IsGroup     bool
}

func (a *Account) toIdentity(externalIDType string, identity *client.Identity) {
	identity.ExternalId = a.UID
	identity.Resource.Id = externalIDType + ":" + a.UID
	identity.ExternalIdType = externalIDType
	if a.DisplayName != "" {
		identity.Name = a.DisplayName
	} else {
		identity.Name = a.UserName
	}
	identity.Login = a.UserName
}
