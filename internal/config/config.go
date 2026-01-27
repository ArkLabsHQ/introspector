package config

import (
	"encoding/hex"
	"fmt"

	"github.com/ArkLabsHQ/introspector/internal/application"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	SecretKey       = "SECRET_KEY"
	Datadir         = "DATADIR"
	Port            = "PORT"
	NoTLS           = "NO_TLS"
	TLSExtraIPs     = "TLS_EXTRA_IPS"
	TLSExtraDomains = "TLS_EXTRA_DOMAINS"
	LogLevel        = "LOG_LEVEL"
)

var (
	defaultDatadir         = arklib.AppDataDir("introspector", false)
	defaultPort            = uint32(7073)
	defaultNoTLS           = false
	defaultTLSExtraIPs     = []string{}
	defaultTLSExtraDomains = []string{}
	defaultLogLevel        = log.DebugLevel
)

type Config struct {
	SecretKey       *btcec.PrivateKey
	Datadir         string
	Port            uint32
	NoTLS           bool
	TLSExtraIPs     []string
	TLSExtraDomains []string
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("INTROSPECTOR")
	viper.AutomaticEnv()

	viper.SetDefault(Datadir, defaultDatadir)
	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(NoTLS, defaultNoTLS)
	viper.SetDefault(TLSExtraIPs, defaultTLSExtraIPs)
	viper.SetDefault(TLSExtraDomains, defaultTLSExtraDomains)
	viper.SetDefault(LogLevel, defaultLogLevel)

	secretKeyHex := viper.GetString(SecretKey)
	secretKeyBytes, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret key: %w", err)
	}
	secretKey, _ := btcec.PrivKeyFromBytes(secretKeyBytes)
	if secretKey == nil {
		return nil, fmt.Errorf("invalid secret key")
	}

	logLevel := viper.GetInt(LogLevel)
	log.SetLevel(log.Level(logLevel))

	cfg := &Config{
		SecretKey:       secretKey,
		Datadir:         viper.GetString(Datadir),
		Port:            viper.GetUint32(Port),
		NoTLS:           viper.GetBool(NoTLS),
		TLSExtraIPs:     viper.GetStringSlice(TLSExtraIPs),
		TLSExtraDomains: viper.GetStringSlice(TLSExtraDomains),
	}
	return cfg, nil
}

func (c *Config) AppService() (application.Service, error) {
	return application.New(c.SecretKey), nil
}
