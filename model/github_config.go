package model

import "github.com/rancher/go-rancher/client"

//GithubConfig stores the github config read from JSON file
type GithubConfig struct {
	client.Resource
	Hostname     string `json:"hostname,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}
