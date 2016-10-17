package model

import "github.com/rancher/go-rancher/client"

//AuthConfig structure contains the AuthConfig definition
type AuthConfig struct {
	client.Resource
	Provider          string            `json:"provider"`
	Enabled           bool              `json:"enabled"`
	AccessMode        string            `json:"accessMode"`
	AllowedIdentities []client.Identity `json:"allowedIdentities"`
	GithubConfig      GithubConfig      `json:"githubConfig"`
	ShibbolethConfig  ShibbolethConfig  `json:"shibbolethConfig"`
}
