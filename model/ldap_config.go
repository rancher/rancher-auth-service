package model

import "github.com/rancher/go-rancher/v2"

// LdapConfig stores the AD config read from JSON file
type LdapConfig struct {
	client.Resource
	Server                      string `json:"server"`
	Port                        int64  `json:"port"`
	UserDisabledBitMask         int64  `json:"userDisabledBitMask"`
	LoginDomain                 string `json:"loginDomain"`
	Domain                      string `json:"domain"`
	GroupSearchDomain           string `json:"groupSearchDomain"`
	ServiceAccountUsername      string `json:"serviceAccountUsername"`
	ServiceAccountPassword      string `json:"serviceAccountPassword"`
	TLS                         bool   `json:"tls"`
	UserSearchField             string `json:"userSearchField"`
	UserLoginField              string `json:"userLoginField"`
	UserObjectClass             string `json:"userObjectClass"`
	UserNameField               string `json:"userNameField"`
	UserEnabledAttribute        string `json:"userEnabledAttribute"`
	GroupSearchField            string `json:"groupSearchField"`
	GroupObjectClass            string `json:"groupObjectClass"`
	GroupNameField              string `json:"groupNameField"`
	GroupDNField                string `json:"groupDNField"`
	GroupMemberUserAttribute    string `json:"groupMemberUserAttribute"`
	GroupMemberMappingAttribute string `json:"groupMemberMappingAttribute"`
	ConnectionTimeout           int64  `json:"connectionTimeout"`
}

//ConnectionTimeout in seconds
