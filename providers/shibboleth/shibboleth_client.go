package shibboleth

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/rancher/rancher-auth-service/model"
)

//SPClient implements a client for shibboleth and the saml library
type SPClient struct {
	config *model.ShibbolethConfig
}

func (spclient *SPClient) initializeSPClient(configToSet *model.ShibbolethConfig) error {
	var idpURL string
	var privKey *rsa.PrivateKey
	var cert *x509.Certificate
	var err error
	var ok bool

	spclient.config = configToSet

	/* After auth is setup, the admin can change the access mode/allowed principals via admin access control page. When the admin clicks on "Save",
	a POST to v1-auth/config is made, which includes the entire model.ShibbolethConfig. During this call, the key and metadata aren't passed by UI
	that's why we won't return an error here, instead we can just return nil */
	if configToSet.IDPMetadataURL == "" {
		idpURL = ""
		if configToSet.IDPMetadataContent == "" {
			if configToSet.IDPMetadataFilePath == "" {
				log.Debugf("SAML: Cannot initialize saml Shibboleth SP properly, missing IDP metadata in the config %v", configToSet)
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
			log.Debugf("SAML: Cannot initialize saml SP properly, missing SpCert in the config %v", configToSet)
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
			log.Debugf("SAML: Cannot initialize saml SP properly, missing SpKey in the config %v", configToSet)
		}
	}

	if configToSet.SPSelfSignedKey != "" {
		// used from ssh.ParseRawPrivateKey
		block, _ := pem.Decode([]byte(configToSet.SPSelfSignedKey))
		if block == nil {
			return fmt.Errorf("no key found")
		}

		if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return fmt.Errorf("cannot decode encrypted private keys")
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("error parsing PKCS1 RSA key: %v", err)
			}
		case "PRIVATE KEY":
			pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("error parsing PKCS8 RSA key: %v", err)
			}
			privKey, ok = pk.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("unable to get rsa key")
			}
		default:
			return fmt.Errorf("unsupported key type %q", block.Type)
		}
	}

	if configToSet.SPSelfSignedCert != "" {
		block, _ := pem.Decode([]byte(configToSet.SPSelfSignedCert))
		if block == nil {
			panic("failed to parse PEM block containing the private key")
		}

		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("failed to parse DER encoded public key: " + err.Error())
		}
	}

	actURL, err := url.Parse(configToSet.RancherAPIHost + "/v1-auth")
	if err != nil {
		return fmt.Errorf("error in parsing URL")
	}

	metadataURL := *actURL
	metadataURL.Path = metadataURL.Path + "/saml/metadata"
	acsURL := *actURL
	acsURL.Path = acsURL.Path + "/saml/acs"

	sp := &saml.ServiceProvider{
		Key:         privKey,
		Certificate: cert,
		MetadataURL: metadataURL,
		AcsURL:      acsURL,
	}

	if err != nil {
		log.Errorf("Error initializing SAML SP instance from the config %v, error %v", configToSet, err)
	}

	cookieStore := samlsp.ClientCookies{
		ServiceProvider: sp,
		Name:            "samlToken",
		Domain:          actURL.Host,
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
		sp.IDPMetadata = &saml.EntityDescriptor{}
		if err := xml.NewDecoder(resp.Body).Decode(sp.IDPMetadata); err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot decode IDP Metadata xml from the config %v, error %v", configToSet, err)
		}
	} else if configToSet.IDPMetadataContent != "" {
		sp.IDPMetadata = &saml.EntityDescriptor{}
		if err := xml.NewDecoder(strings.NewReader(configToSet.IDPMetadataContent)).Decode(sp.IDPMetadata); err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot decode IDP Metadata content from the config %v, error %v", configToSet, err)
		}
	} else if configToSet.IDPMetadataFilePath != "" {
		file, err := os.Open(configToSet.IDPMetadataFilePath)
		if err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot read IDP Metadata file from the config %v, error %v", configToSet, err)
		}
		metadataReader := bufio.NewReader(file)
		sp.IDPMetadata = &saml.EntityDescriptor{}
		if err := xml.NewDecoder(metadataReader).Decode(sp.IDPMetadata); err != nil {
			return fmt.Errorf("Cannot initialize saml Shibboleth SP, cannot decode IDP Metadata xml from the config %v, error %v", configToSet, err)
		}
	}

	rsp := &model.RancherSamlServiceProvider{
		ServiceProvider: *sp,
		ClientState:     cookieStore,
	}

	configToSet.SamlServiceProvider = rsp
	return nil
}

func (spclient *SPClient) getShibIdentities(samlData map[string][]string) ([]Account, error) {
	//look for saml attributes set in the config
	var shibAccts []Account

	uid, ok := samlData[spclient.config.UIDField]
	if ok {
		shibAcct := Account{}
		shibAcct.UID = uid[0]

		displayName, ok := samlData[spclient.config.DisplayNameField]
		if ok {
			shibAcct.DisplayName = displayName[0]
		}

		userName, ok := samlData[spclient.config.UserNameField]
		if ok {
			shibAcct.UserName = userName[0]
		}
		shibAcct.IsGroup = false

		shibAccts = append(shibAccts, shibAcct)

		groups, ok := samlData[spclient.config.GroupsField]
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
