# rancher-auth-service
A REST Service listening on port 8090 that implements authentication Identity providers to support the Rancher Auth Framework. Initial version comes with github support. It uses the pluggable provider model to implement other providers later. 

The service reads the provider configuration from a json file provided at startup.

APIs exposed are:

POST /v1-rancher-auth/token  
This API authenticates with the actual auth provider(like github) and returns a JWT token to be used for further communication with the service

GET /v1-rancher-auth/me/identities
This API lists the user details and his/her group memberships, for the user identified by the token set in Authorization header

GET /v1-rancher-auth/identities?name=
This API searches for a user/group by name on the backend auth provider

GET /v1-rancher-auth/identities?externalId=&externalIdType=
This API searches for a user/group by Id and type(user/group/team) on the backend auth provider

# Build the go service
godep go build

# Run the go service

Usage of ./rancher-auth-service:
  -configFile string
    	Path of the Config file 
  -debug
    	Debug
  -log string
    	Log file
  -privateKeyFile string
    	Path of file containing RSA Private key 
  -provider string
    	External provider name
  -publicKeyFile string
    	Path of file containing RSA Public key

# The config file for github should be a json file providing the github client_id and client_secret. Example:

{"client_id": "", "client_secret": ""}

# The RSA public and private keys are needed to sign the JWT token provided by /token API
