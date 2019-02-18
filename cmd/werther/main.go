/*
Copyright (C) JSC iCore - All Rights Reserved

Unauthorized copying of this file, via any medium is strictly prohibited
Proprietary and confidential

Written by Konstantin Lepa <klepa@i-core.ru>, July 2018
*/

package main // import "gopkg.i-core.ru/werther/cmd/werther"

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"gopkg.i-core.ru/werther/internal/server"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n")
		if err := envconfig.Usagef("werther", &server.Config{}, flag.CommandLine.Output(), envconfig.DefaultListFormat); err != nil {
			panic(err)
		}
	}
	verflag := flag.Bool("version", false, "print a version")
	flag.Parse()

	if *verflag {
		fmt.Println("werther", server.Version)
		os.Exit(0)
	}

	var cnf server.Config
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

	srv, err := server.New(cnf, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start the server: %s\n", err)
		os.Exit(1)
	}

	log = log.Named("main")
	log.Info("Werther started", zap.Any("config", cnf), zap.String("version", server.Version))
	log.Fatal("Werther finished", zap.Error(http.ListenAndServe(cnf.Listen, srv)))
}
