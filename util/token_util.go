package util

import (
	"crypto/rsa"
	log "github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	"io/ioutil"
)

//CreateTokenWithPayload returns signed jwt token
func CreateTokenWithPayload(payload map[string]interface{}, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	claims := make(jwt.MapClaims)

	for key, value := range payload {
		claims[key] = value
	}

	token.Claims = claims
	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Errorf("Failed to sign the token using the private key, error %v", err)
		return "", err
	}
	return signed, nil
}

//ParsePrivateKey Parses privateKey file
func ParsePrivateKey(filePath string) *rsa.PrivateKey {
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}
	return privateKeyDecode(keyBytes)
}

//ParsePrivateKeyContents Parses rsa Key contents
func ParsePrivateKeyContents(keyFileContents string) *rsa.PrivateKey {
	return privateKeyDecode([]byte(keyFileContents))
}

//privateKeyDecode Parses rsa key bytes
func privateKeyDecode(keyBytes []byte) *rsa.PrivateKey {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatal("Failed to parse private key.", err)
	}
	return privateKey
}

//ParsePublicKey Parses publicKey file
func ParsePublicKey(filePath string) *rsa.PublicKey {
	keyBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal("Failed to parse public key.", err)
	}
	return publicKeyDecode(keyBytes)
}

//ParsePublicKeyContents Parses rsa Key contents
func ParsePublicKeyContents(keyFileContents string) *rsa.PublicKey {
	return publicKeyDecode([]byte(keyFileContents))
}

//publicKeyDecode Parses rsa key bytes
func publicKeyDecode(keyBytes []byte) *rsa.PublicKey {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		log.Fatal("Failed to parse public key.", err)
	}
	return publicKey
}
