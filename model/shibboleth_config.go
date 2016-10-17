package model

import (
	"github.com/crewjam/saml/samlsp"
	"github.com/rancher/go-rancher/client"
)

//ShibbolethConfig stores the shibboleth config
type ShibbolethConfig struct {
	client.Resource
	IDPMetadataURL     string `json:"idpMetadataUrl"`
	IDPMetadataContent string `json:"idpMetadataContent"`
	SPSelfSignedCert   string `json:"spCert"`
	SPSelfSignedKey    string `json:"spKey"`
	GroupsField        string `json:"groupsField"`
	DisplayNameField   string `json:"displayNameField"`
	UserNameField      string `json:"userNameField"`
	UIDField           string `json:"uidField"`

	IDPMetadataFilePath      string
	SPSelfSignedCertFilePath string
	SPSelfSignedKeyFilePath  string
	RancherAPIHost           string

	SamlServiceProvider *samlsp.Middleware
}
