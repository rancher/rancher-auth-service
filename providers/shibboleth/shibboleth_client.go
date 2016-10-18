package shibboleth

import (
	"bufio"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/rancher/rancher-auth-service/model"
)

//SPClient implements a client for shibboleth and the saml library
type SPClient struct {
	config *model.ShibbolethConfig
	samlSP *samlsp.Middleware
}

func (sp *SPClient) initializeSPClient(configToSet *model.ShibbolethConfig) error {

	var idpURL string

	sp.config = configToSet

	if configToSet.IDPMetadataURL == "" {
		idpURL = ""
		if configToSet.IDPMetadataContent == "" {
			if configToSet.IDPMetadataFilePath == "" {
				log.Debugf("Cannot initialize saml Shibboleth SP properly, missing IDP URL/metadata in the config %v", configToSet)
			}
		}
	} else {
		idpURL = configToSet.IDPMetadataURL
	}

	if configToSet.SPSelfSignedCert == "" {
		if configToSet.SPSelfSignedCertFilePath != "" {
			cert, err := ioutil.ReadFile(configToSet.SPSelfSignedCertFilePath)
			if err != nil {
				log.Errorf("Cannot initialize saml Shibboleth SP, cannot read SPSelfSignedCert file in the config %v, error %v", configToSet, err)
			}
			configToSet.SPSelfSignedCert = string(cert)
		} else {
			log.Debugf("Cannot initialize saml Shibboleth SP properly, missing SPSelfSignedCert in the config %v", configToSet)
		}
	}

	if configToSet.SPSelfSignedKey == "" {
		if configToSet.SPSelfSignedKeyFilePath != "" {
			key, err := ioutil.ReadFile(configToSet.SPSelfSignedKeyFilePath)
			if err != nil {
				return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot read SPSelfSignedKey file in the config %v, error %v", configToSet, err)
			}
			configToSet.SPSelfSignedKey = string(key)
		} else {
			log.Debugf("Cannot initialize saml Shibboleth SP properly, missing SPSelfSignedKey in the config %v", configToSet)
		}
	}

	samlspInstance, err := samlsp.New(samlsp.Options{
		IDPMetadataURL: "",
		URL:            configToSet.RancherAPIHost + "/v1-auth",
		Key:            string(configToSet.SPSelfSignedKey),
		Certificate:    string(configToSet.SPSelfSignedCert),
	})

	if err != nil {
		log.Errorf("Error initializing SAML SP instance from the config %v, error %v", configToSet, err)
	}

	if idpURL != "" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get(idpURL)
		if err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot get IDP Metadata  from the url %v, error %v", idpURL, err)
		}
		samlspInstance.ServiceProvider.IDPMetadata = &saml.Metadata{}
		if err := xml.NewDecoder(resp.Body).Decode(samlspInstance.ServiceProvider.IDPMetadata); err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot decode IDP Metadata xml from the config %v, error %v", configToSet, err)
		}
	} else if configToSet.IDPMetadataContent != "" {
		samlspInstance.ServiceProvider.IDPMetadata = &saml.Metadata{}
		if err := xml.NewDecoder(strings.NewReader(configToSet.IDPMetadataContent)).Decode(samlspInstance.ServiceProvider.IDPMetadata); err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot decode IDP Metadata content from the config %v, error %v", configToSet, err)
		}
	} else if configToSet.IDPMetadataFilePath != "" {
		file, err := os.Open(configToSet.IDPMetadataFilePath)
		if err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot read IDP Metadata file from the config %v, error %v", configToSet, err)
		}
		metadataReader := bufio.NewReader(file)
		samlspInstance.ServiceProvider.IDPMetadata = &saml.Metadata{}
		if err := xml.NewDecoder(metadataReader).Decode(samlspInstance.ServiceProvider.IDPMetadata); err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot decode IDP Metadata xml from the config %v, error %v", configToSet, err)
		}

	}
	configToSet.SamlServiceProvider = samlspInstance
	sp.samlSP = configToSet.SamlServiceProvider
	return nil
}

func (sp *SPClient) getShibIdentities(samlData map[string][]string) ([]Account, error) {
	//look for saml attributes set in the config

	var shibAccts []Account

	uid, ok := samlData[strings.ToLower(sp.config.UIDField)]
	if ok {
		shibAcct := Account{}
		shibAcct.UID = uid[0]

		displayName, ok := samlData[strings.ToLower(sp.config.DisplayNameField)]
		if ok {
			shibAcct.DisplayName = displayName[0]
		}

		userName, ok := samlData[strings.ToLower(sp.config.UserNameField)]
		if ok {
			shibAcct.UserName = userName[0]
		}
		shibAcct.IsGroup = false

		shibAccts = append(shibAccts, shibAcct)

		groups, ok := samlData[strings.ToLower(sp.config.GroupsField)]
		if ok {
			for _, group := range groups {
				groupAcct := Account{}
				groupAcct.UID = group
				groupAcct.IsGroup = true
				groupAcct.DisplayName = group
				shibAccts = append(shibAccts, groupAcct)
			}
		}
	}

	return shibAccts, nil
}
