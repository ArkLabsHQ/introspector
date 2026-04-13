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
	SecretKey               = "SECRET_KEY"
	Datadir                 = "DATADIR"
	Port                    = "PORT"
	NoTLS                   = "NO_TLS"
	TLSExtraIPs             = "TLS_EXTRA_IPS"
	TLSExtraDomains         = "TLS_EXTRA_DOMAINS"
	LogLevel                = "LOG_LEVEL"
	ArkdURL                 = "ARKD_URL"
	FinalizeMaxRetries      = "FINALIZE_MAX_RETRIES"
	FinalizeMinRetryDelayMs = "FINALIZE_MIN_RETRY_DELAY_MS"
	FinalizeMaxRetryDelayMs = "FINALIZE_MAX_RETRY_DELAY_MS"
)

var (
	defaultDatadir                 = arklib.AppDataDir("introspector", false)
	defaultPort                    = uint32(7073)
	defaultNoTLS                   = false
	defaultTLSExtraIPs             = []string{}
	defaultTLSExtraDomains         = []string{}
	defaultLogLevel                = log.DebugLevel
	defaultFinalizeMaxRetries      = 10
	defaultFinalizeMinRetryDelayMs = 250
	defaultFinalizeMaxRetryDelayMs = 1500
)

type Config struct {
	SecretKey               *btcec.PrivateKey
	Datadir                 string
	Port                    uint32
	NoTLS                   bool
	TLSExtraIPs             []string
	TLSExtraDomains         []string
	ArkdURL                 string
	FinalizeMaxRetries      int
	FinalizeMinRetryDelayMs int
	FinalizeMaxRetryDelayMs int
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
	viper.SetDefault(FinalizeMaxRetries, defaultFinalizeMaxRetries)
	viper.SetDefault(FinalizeMinRetryDelayMs, defaultFinalizeMinRetryDelayMs)
	viper.SetDefault(FinalizeMaxRetryDelayMs, defaultFinalizeMaxRetryDelayMs)

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
		SecretKey:               secretKey,
		Datadir:                 viper.GetString(Datadir),
		Port:                    viper.GetUint32(Port),
		NoTLS:                   viper.GetBool(NoTLS),
		TLSExtraIPs:             viper.GetStringSlice(TLSExtraIPs),
		TLSExtraDomains:         viper.GetStringSlice(TLSExtraDomains),
		ArkdURL:                 viper.GetString(ArkdURL),
		FinalizeMaxRetries:      viper.GetInt(FinalizeMaxRetries),
		FinalizeMinRetryDelayMs: viper.GetInt(FinalizeMinRetryDelayMs),
		FinalizeMaxRetryDelayMs: viper.GetInt(FinalizeMaxRetryDelayMs),
	}
	if cfg.ArkdURL == "" {
		return nil, fmt.Errorf("missing arkd url")
	}
	if cfg.FinalizeMaxRetries < 0 {
		return nil, fmt.Errorf("invalid finalize max retries")
	}
	if cfg.FinalizeMinRetryDelayMs < 0 {
		return nil, fmt.Errorf("invalid finalize min retry delay")
	}
	if cfg.FinalizeMaxRetryDelayMs < cfg.FinalizeMinRetryDelayMs {
		return nil, fmt.Errorf("finalize max retry delay must be >= min retry delay")
	}
	return cfg, nil
}

func (c *Config) AppService() (application.Service, error) {
	return application.New(c.SecretKey, c.ArkdURL, application.FinalizeRetryPolicy{
		MaxRetries:           c.FinalizeMaxRetries,
		MinDelayMilliseconds: c.FinalizeMinRetryDelayMs,
		MaxDelayMilliseconds: c.FinalizeMaxRetryDelayMs,
	}), nil
}
