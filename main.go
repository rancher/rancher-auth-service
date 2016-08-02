package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/rancher/rancher-auth-service/server"
	"github.com/rancher/rancher-auth-service/service"
	"net/http"
)

func main() {
	server.SetEnv()
	StartService()
}

func StartService() {

	log.Info("Starting Rancher Auth service")

	router := service.NewRouter()

	//log.Info("Listening on ", c.GlobalString("listen"))
	log.Fatal(http.ListenAndServe(":8090", router))

}
