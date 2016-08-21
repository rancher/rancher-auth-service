package model

import "github.com/rancher/go-rancher/client"

//AuthServiceError structure contains the error resource definition
type AuthServiceError struct {
	client.Resource
	Status  string `json:"status"`
	Message string `json:"message"`
}
