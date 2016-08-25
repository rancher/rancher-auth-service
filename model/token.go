package model

import (
	"github.com/rancher/go-rancher/client"
)

//Token structure defines all properties that can be present in a token
type Token struct {
	client.Resource
	Type              string            `json:"tokenType"`
	ExternalAccountID string            `json:"accountID"`
	IdentityList      []client.Identity `json:"identities"`
	AccessToken       string
	JwtToken          string `json:"jwt"`
}
