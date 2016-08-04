package model

import (
	"github.com/rancher/go-rancher/client"
)

//Token structure defines all properties that can be present in a token
type Token struct {
	Type string 
	ExternalAccountID   string
	IdentityList []client.Identity
	AccessToken string
}