/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential
*/

package main // import "gopkg.i-core.ru/werther/cmd/werther"

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/justinas/nosurf"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"gopkg.i-core.ru/httputil"
	"gopkg.i-core.ru/logutil"
	"gopkg.i-core.ru/werther/internal/identp"
	"gopkg.i-core.ru/werther/internal/ldapclient"
	"gopkg.i-core.ru/werther/internal/stat"
	"gopkg.i-core.ru/werther/internal/web"
)

// Version will be filled at compile time.
var Version = ""

// Config is a server's configuration.
type Config struct {
	DevMode bool   `envconfig:"dev_mode" default:"false" desc:"a development mode"`
	Listen  string `default:":8080" desc:"a host and port to listen on (<host>:<port>)"`
	Web     web.Config
	Identp  identp.Config
	LDAP    ldapclient.Config
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n")
		if err := envconfig.Usagef("werther", &Config{}, flag.CommandLine.Output(), envconfig.DefaultListFormat); err != nil {
			panic(err)
		}
	}
	verflag := flag.Bool("version", false, "print a version")
	flag.Parse()

	if *verflag {
		fmt.Println("werther", Version)
		os.Exit(0)
	}

	var cnf Config
	if err := envconfig.Process("werther", &cnf); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %s\n", err)
		os.Exit(1)
	}

	logFunc := zap.NewProduction
	if cnf.DevMode {
		logFunc = zap.NewDevelopment
	}
	log, err := logFunc()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %s\n", err)
		os.Exit(1)
	}

	htmlRenderer, err := web.NewHTMLRenderer(cnf.Web)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start the server: %s\n", err)
		os.Exit(1)
	}

	ldap := ldapclient.New(cnf.LDAP)

	router := httputil.NewRouter(nosurf.NewPure, logutil.RequestLog(log))
	router.AddRoutes(web.NewStaticHandler(cnf.Web), "/static")
	router.AddRoutes(identp.NewHandler(cnf.Identp, ldap, htmlRenderer), "/auth")
	router.AddRoutes(stat.NewHandler(Version), "/stat")

	log = log.Named("main")
	log.Info("Werther started", zap.Any("config", cnf), zap.String("version", Version))
	log.Fatal("Werther finished", zap.Error(http.ListenAndServe(cnf.Listen, router)))
}
