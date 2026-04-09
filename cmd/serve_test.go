package cmd

import (
	"testing"
)

func TestResolveAddr_FlagOverridesConfig(t *testing.T) {
	flagAddr := ":9999"
	cfgAddr := "127.0.0.1:8080"
	got := resolveAddr(flagAddr, cfgAddr)
	if got != ":9999" {
		t.Errorf("want :9999, got %s", got)
	}
}

func TestResolveAddr_ConfigUsedWhenNoFlag(t *testing.T) {
	flagAddr := ""
	cfgAddr := "127.0.0.1:9090"
	got := resolveAddr(flagAddr, cfgAddr)
	if got != "127.0.0.1:9090" {
		t.Errorf("want 127.0.0.1:9090, got %s", got)
	}
}

func TestResolveAddr_DefaultAddrFromConfig(t *testing.T) {
	got := resolveAddr("", "127.0.0.1:8080")
	if got != "127.0.0.1:8080" {
		t.Errorf("want 127.0.0.1:8080, got %s", got)
	}
}
