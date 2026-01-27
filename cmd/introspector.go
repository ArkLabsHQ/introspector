package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/ArkLabsHQ/introspector/internal/config"
	grpcservice "github.com/ArkLabsHQ/introspector/internal/interface/grpc"
	log "github.com/sirupsen/logrus"
)

const (
	Version = "fugazi" // TODO
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	log.WithFields(log.Fields{
		"version":           Version,
		"port":              cfg.Port,
		"no_tls":            cfg.NoTLS,
		"tls_extra_ips":     cfg.TLSExtraIPs,
		"tls_extra_domains": cfg.TLSExtraDomains,
		"datadir":           cfg.Datadir,
	}).Info("config loaded")

	svc, err := grpcservice.NewService(Version, cfg)
	if err != nil {
		log.Fatalf("failed to create service: %s", err)
	}

	log.Debug("starting service...")
	if err := svc.Start(); err != nil {
		log.Fatalf("failed to start service: %s", err)
	}

	log.RegisterExitHandler(svc.Stop)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, os.Interrupt)
	<-sigChan

	log.Debug("shutting down service...")
	log.Exit(0)
}
