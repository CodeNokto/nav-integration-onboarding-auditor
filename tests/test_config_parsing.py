from pathlib import Path

from nav_integration_onboarding_auditor import OnboardingConfig, parse_config


def test_parse_example_config() -> None:
    cfg = parse_config(Path("onboarding.config.example.json"))
    assert isinstance(cfg, OnboardingConfig)
    assert "dev" in cfg.environments

    env = cfg.environments["dev"]
    assert "demo-partner" in env.partners
    partner = env.partners["demo-partner"]
    assert partner.base_url.startswith("https://")

    assert "nav-test-api" in env.nav_apis
    nav_api = env.nav_apis["nav-test-api"]
    assert nav_api.base_url.startswith("https://")
