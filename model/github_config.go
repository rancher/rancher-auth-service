package model

import "github.com/rancher/go-rancher/client"

//GithubConfig stores the github config read from JSON file
type GithubConfig struct {
	client.Resource
	Hostname     string `json:"hostname"`
	Scheme       string `json:"scheme"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}
