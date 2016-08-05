# rancher-auth-service
A REST Service listening on port 8090 that implements authentication Identity providers to support the Rancher Auth Framework. Initial version comes with github support. It uses the pluggable provider model to implement other providers later. 


APIs exposed are:

POST /v1-rancher-auth/config
This will save the provided config to the Cattle Database as settings and initialize the auth provider with the given config

GET /v1-rancher-auth/config
This will list the auth config from settings table in Cattle Database

POST /v1-rancher-auth/reload
This will read the auth config from settings table in Cattle Database and re-initialize the auth provider

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
  -debug
    	Debug
  -log string
    	Log file
  -privateKeyFile string
    	Path of file containing RSA Private key 
  -publicKeyFile string
    	Path of file containing RSA Public key

The RSA public and private keys are needed to sign the JWT token provided by /token API

# Required Environment Variables:

Set the Cattle service account and secret key to the Environment
export CATTLE_ACCESS_KEY= <service account key>
export CATTLE_SECRET_KEY= <service account secret key>
