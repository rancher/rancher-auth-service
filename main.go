package main

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/rancher/rancher-auth-service/server"
	"github.com/rancher/rancher-auth-service/service"
	"net/http"
	"os"
)

func beforeApp(c *cli.Context) error {
	if c.GlobalBool("verbose") {
		log.SetLevel(log.DebugLevel)
	}
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "rancher-auth-service"
	app.Usage = "Rancher auth service supporting external auth providers"
	app.Author = "Rancher Labs, Inc."
	app.Email = ""
	app.Before = beforeApp
	app.Action = StartService
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name: "rsa-public-key",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing RSA public key",
			),
		},
		cli.StringFlag{
			Name: "rsa-private-key",
			Usage: fmt.Sprintf(
				"Specify the path to the file containing RSA private key",
			),
		},
		cli.StringFlag{
			Name: "cattle-url",
			Usage: fmt.Sprintf(
				"Specify Cattle endpoint URL",
			),
			EnvVar: "CATTLE_URL",
		},
		cli.StringFlag{
			Name: "cattle-access-key",
			Usage: fmt.Sprintf(
				"Specify Cattle access key",
			),
			EnvVar: "CATTLE_ACCESS_KEY",
		},
		cli.StringFlag{
			Name: "cattle-secret-key",
			Usage: fmt.Sprintf(
				"Specify Cattle secret key",
			),
			EnvVar: "CATTLE_SECRET_KEY",
		},
		cli.BoolFlag{
			Name: "debug",
			Usage: fmt.Sprintf(
				"Set true to get debug logs",
			),
		},
		cli.StringFlag{
			Name:  "listen",
			Value: ":8090",
			Usage: fmt.Sprintf(
				"Address to listen to (TCP)",
			),
		},
	}

	app.Run(os.Args)
}

func StartService(c *cli.Context) {

	server.SetEnv(c)

	if c.GlobalBool("debug") {
		log.SetLevel(log.DebugLevel)
	}

	textFormatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(textFormatter)

	log.Info("Starting Rancher Auth service")

	router := service.NewRouter()

	log.Info("Listening on ", c.GlobalString("listen"))
	log.Fatal(http.ListenAndServe(c.GlobalString("listen"), router))

}
