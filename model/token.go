package model

import (
	"github.com/rancher/go-rancher/client"
)

type Token struct {
	Type string 
	ExternalAccountId   string
	IdentityList []client.Identity
	AccessToken string
}