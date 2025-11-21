# NAV Integration Onboarding Auditor

CLI-verktøy for å kjøre enkle «onboarding-audits» av NAV-integrasjoner:
- tester at token-oppsett (Maskinporten/Azure AD) er gyldig,
- verifiserer at partner-endepunkter svarer fornuftig,
- verifiserer at NAV-endepunkter svarer fornuftig,
- produserer JSON-rapporter og exit-koder som kan brukes i CI/CD.

> Dette er et uoffisielt open source-verktøy laget på eget initiativ for å forenkle arbeid med NAV-API-er.
> Prosjektet er ikke bestilt eller driftet av NAV, men kan brukes som støtteverktøy av integrasjonspartnere og utviklere.

## Hva verktøyet løser

- Ett sted å beskrive miljø, partnere og NAV-API-er i en strukturert config-fil.
- Én kommando for å teste om Maskinporten/Azure AD-oppsettet faktisk gir tokens.
- Én kommando for å sjekke om partner-endepunkter svarer (statuskode + responstid).
- Én kommando for å sjekke om NAV-endepunkter svarer (statuskode + responstid).
- JSON-rapport på standard format for alle audits, egnet for CI/CD.
- Exit-koder (0/1) slik at pipelines kan stoppe deploy når integrasjonen er knekt.

## Filstruktur

- `nav_integration_onboarding_auditor.py` – hoved-CLI.
- `onboarding.config.example.json` – eksempel på full config for miljøer, partnere og NAV-API-er.
- `requirements.txt` – avhengigheter (requests, PyJWT, pytest).
- `tests/test_config_parsing.py` – enkel test av config-parsing.
- `.github/workflows/ci.yml` – GitHub Actions-workflow for lint/pytest/compile.
- `.gitignore` – standard Python + lokale hemmeligheter.

## Installasjon lokalt

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
```

## Konfigurasjon

Kopier eksempelconfigen:

```bash
cp onboarding.config.example.json onboarding.config.json
```

Viktige felter:

- `default_env` – navn på standardmiljø.
- `environments.<navn>.maskinporten` – Maskinporten-oppsett (valgfritt).
- `environments.<navn>.azure_ad` – Azure AD-oppsett (valgfritt).
- `environments.<navn>.partners` – partner-definisjoner.
- `environments.<navn>.nav_apis` – NAV-API-definisjoner.

Eksempelconfigen bruker `https://httpbin.org` som demo-endepunkt for å kunne kjøre uten ekte hemmeligheter.

## Eksempelbruk

Audit av tokens (maskinporten/azure_ad avhengig av config):

```bash
python nav_integration_onboarding_auditor.py --config onboarding.config.json --env dev tokens --output tokens_report.json
```

Audit av én partner (navn fra config):

```bash
python nav_integration_onboarding_auditor.py --config onboarding.config.json --env dev partner --name demo-partner --output partner_demo_report.json
```

Audit av ett NAV-API (navn fra config):

```bash
python nav_integration_onboarding_auditor.py --config onboarding.config.json --env dev nav --name nav-test-api --output nav_test_api_report.json
```

## CI

Repoet er satt opp med en GitHub Actions-workflow som:

- installerer dependencies,
- kjører pytest (bare config-parsing, ingen nettverkskall),
- kompilerer alle .py-filer (`python -m compileall .`).

Dette er nok til å vise at prosjektet er testbart og byggbart uten ekstra oppsett.
Dette er et uoffisielt open source-verktøy laget på eget initiativ for å gjøre arbeid med NAV-API-er enklere i praksis. 
Verktøyet er ikke bestilt eller driftet av NAV, men kan brukes som støtteverktøy av utviklere og integrasjonspartnere.
