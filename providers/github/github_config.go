package github

import ()

//GithubConfig stores the github config read from JSON file
type GithubConfig struct {
	Hostname     string `json:"hostname,omitempty"`
	Scheme       string `json:"scheme,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}
