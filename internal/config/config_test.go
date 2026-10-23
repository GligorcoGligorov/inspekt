package config

import "testing"

// A key and model in the environment (e.g. from .env) must not be enough to
// send mail to an LLM provider: only INSPEKT_LLM_ENABLED=true turns it on.
func TestLLMNeedsExplicitEnable(t *testing.T) {
	t.Setenv("INSPEKT_LLM_BASE_URL", "https://api.example.test/v1")
	t.Setenv("INSPEKT_LLM_MODEL", "some-model")
	t.Setenv("INSPEKT_LLM_API_KEY", "secret")

	for _, v := range []string{"", "false", "1", "TRUE", "yes"} {
		t.Setenv("INSPEKT_LLM_ENABLED", v)
		cfg, err := Engine(nil)
		if err != nil || cfg.Reviewer != nil || LLM() != "off" {
			t.Errorf("INSPEKT_LLM_ENABLED=%q: reviewer %v, err %v, LLM() %q", v, cfg.Reviewer, err, LLM())
		}
	}

	t.Setenv("INSPEKT_LLM_ENABLED", "true")
	if cfg, err := Engine(nil); err != nil || cfg.Reviewer == nil {
		t.Fatalf("enabled: reviewer %v, err %v", cfg.Reviewer, err)
	}
	t.Setenv("INSPEKT_LLM_BASE_URL", "")
	if _, err := Engine(nil); err == nil {
		t.Fatal("enabled without a base URL must be an error")
	}
}
