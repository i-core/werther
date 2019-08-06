/*
Copyright (c) JSC iCore.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package main // import "github.com/i-core/werther/cmd/werther"

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/i-core/rlog"
	"github.com/i-core/routegroup"
	"github.com/i-core/werther/internal/identp"
	"github.com/i-core/werther/internal/ldapclient"
	"github.com/i-core/werther/internal/stat"
	"github.com/i-core/werther/internal/web"
	"github.com/justinas/nosurf"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
)

// version will be filled at compile time.
var version = ""

// Config is a server's configuration.
type Config struct {
	DevMode bool   `envconfig:"dev_mode" default:"false" desc:"a development mode"`
	Listen  string `default:":8080" desc:"a host and port to listen on (<host>:<port>)"`
	Identp  identp.Config
	LDAP    ldapclient.Config
	Web     web.Config
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
		fmt.Println("werther", version)
		os.Exit(0)
	}

	var cnf Config
	if err := envconfig.Process("werther", &cnf); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %s\n", err)
		os.Exit(1)
	}
	if _, ok := cnf.Identp.ClaimScopes[url.QueryEscape(cnf.LDAP.RoleClaim)]; !ok {
		fmt.Fprintf(os.Stderr, "Roles claim %q has no mapping to an OpenID Connect scope\n", cnf.LDAP.RoleClaim)
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

	router := routegroup.NewRouter(nosurf.NewPure, rlog.NewMiddleware(log))
	router.AddRoutes(web.NewStaticHandler(cnf.Web), "/static")
	router.AddRoutes(identp.NewHandler(cnf.Identp, ldap, htmlRenderer), "/auth")
	router.AddRoutes(stat.NewHandler(version), "/stat")

	log = log.Named("main")
	log.Info("Werther started", zap.Any("config", cnf), zap.String("version", version))
	log.Fatal("Werther finished", zap.Error(http.ListenAndServe(cnf.Listen, router)))
}
