package cmdutil

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("CM_TEST_EMPTY", "   ")
	t.Setenv("CM_TEST_VALUE", " value ")

	if got := EnvOrDefault("CM_TEST_EMPTY", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback for empty env, got %q", got)
	}
	if got := EnvOrDefault("CM_TEST_VALUE", "fallback"); got != "value" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
}

func TestEnvOrDefaultSupportsLegacyDockerKeys(t *testing.T) {
	t.Setenv("CM_NODE_ID", "")
	t.Setenv("NODE_ID", "")
	t.Setenv("node-id", " legacy-node ")

	if got := EnvOrDefault("CM_NODE_ID", "fallback"); got != "legacy-node" {
		t.Fatalf("expected legacy docker env to win, got %q", got)
	}
}

func TestEnvDuration(t *testing.T) {
	t.Setenv("CM_TEST_DURATION", "15s")
	t.Setenv("CM_TEST_BAD_DURATION", "abc")

	if got := EnvDuration("CM_TEST_DURATION", time.Second); got != 15*time.Second {
		t.Fatalf("expected 15s, got %s", got)
	}
	if got := EnvDuration("CM_TEST_BAD_DURATION", 3*time.Second); got != 3*time.Second {
		t.Fatalf("expected fallback duration, got %s", got)
	}
}

func TestEnvDurationSupportsLegacyDockerKeys(t *testing.T) {
	t.Setenv("CM_TEST_INTERVAL", "")
	t.Setenv("test-interval", "12s")

	if got := EnvDuration("CM_TEST_INTERVAL", time.Second); got != 12*time.Second {
		t.Fatalf("expected legacy duration env, got %s", got)
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("CM_TEST_TRUE", " true ")
	t.Setenv("CM_TEST_FALSE", "0")
	t.Setenv("CM_TEST_BAD_BOOL", "maybe")

	if got := EnvBool("CM_TEST_TRUE", false); !got {
		t.Fatal("expected true bool env value")
	}
	if got := EnvBool("CM_TEST_FALSE", true); got {
		t.Fatal("expected false bool env value")
	}
	if got := EnvBool("CM_TEST_BAD_BOOL", true); !got {
		t.Fatal("expected fallback bool value for invalid input")
	}
}

func TestEnvBoolSupportsLegacyDockerKeys(t *testing.T) {
	t.Setenv("CM_DISABLE_UPDATE", "")
	t.Setenv("disable-update", "true")

	if got := EnvBool("CM_DISABLE_UPDATE", false); !got {
		t.Fatal("expected legacy bool env value")
	}
}

func TestEnvBoolPrefersExplicitZeroOverLegacyTrue(t *testing.T) {
	t.Setenv("CM_DISABLE_UPDATE", "0")
	t.Setenv("disable-update", "true")

	if got := EnvBool("CM_DISABLE_UPDATE", true); got {
		t.Fatal("expected explicit CM_DISABLE_UPDATE=0 to win over legacy true value")
	}
}

func TestParseCommaList(t *testing.T) {
	got := ParseCommaList(" eth0, ,en0, lo0 ")
	want := []string{"eth0", "en0", "lo0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestNormalizeListen(t *testing.T) {
	cases := map[string]string{
		"":            "",
		" 8080 ":      ":8080",
		":25012":      ":25012",
		"127.0.0.1:9": "127.0.0.1:9",
	}
	for input, want := range cases {
		if got := NormalizeListen(input); got != want {
			t.Fatalf("normalize %q: want %q, got %q", input, want, got)
		}
	}
}

func TestDefaultHostnameFallback(t *testing.T) {
	if os.Getenv("CM_CMDUTIL_SKIP_HOSTNAME") != "" {
		t.Skip("skipped in forced environment")
	}
	got := DefaultHostname()
	if got == "" {
		t.Fatal("expected non-empty hostname")
	}
}

func TestDefaultDataDir(t *testing.T) {
	t.Parallel()

	if got := DefaultDataDir(); got != "./data" {
		t.Fatalf("expected default data dir ./data, got %q", got)
	}
}
