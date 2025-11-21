from __future__ import annotations

import sys
from pathlib import Path

# Sørg for at prosjektroten ligger på sys.path når testen kjører i CI
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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
