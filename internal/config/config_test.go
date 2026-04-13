package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const testSecretKeyHex = "0000000000000000000000000000000000000000000000000000000000000001"

func TestLoadConfigRequiresArkdURL(t *testing.T) {
	viper.Reset()
	t.Setenv("INTROSPECTOR_SECRET_KEY", testSecretKeyHex)

	cfg, err := LoadConfig()
	require.Nil(t, cfg)
	require.ErrorContains(t, err, "missing arkd url")
}

func TestLoadConfigRejectsInvalidFinalizeSettings(t *testing.T) {
	tests := []struct {
		name        string
		envKey      string
		envValue    string
		otherEnvKey string
		otherEnvVal string
		errText     string
	}{
		{
			name:     "negative max retries",
			envKey:   "INTROSPECTOR_FINALIZE_MAX_RETRIES",
			envValue: "-1",
			errText:  "invalid finalize max retries",
		},
		{
			name:     "negative min retry delay",
			envKey:   "INTROSPECTOR_FINALIZE_MIN_RETRY_DELAY_MS",
			envValue: "-1",
			errText:  "invalid finalize min retry delay",
		},
		{
			name:        "max retry delay below min retry delay",
			envKey:      "INTROSPECTOR_FINALIZE_MIN_RETRY_DELAY_MS",
			envValue:    "300",
			otherEnvKey: "INTROSPECTOR_FINALIZE_MAX_RETRY_DELAY_MS",
			otherEnvVal: "200",
			errText:     "finalize max retry delay must be >= min retry delay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Setenv("INTROSPECTOR_SECRET_KEY", testSecretKeyHex)
			t.Setenv("INTROSPECTOR_ARKD_URL", "arkd:7070")
			t.Setenv(tt.envKey, tt.envValue)
			if tt.otherEnvKey != "" {
				t.Setenv(tt.otherEnvKey, tt.otherEnvVal)
			}

			cfg, err := LoadConfig()
			require.Nil(t, cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errText)
		})
	}
}
