#!/usr/bin/env python3
\"\"\"NAV Integration Onboarding Auditor.

CLI-verktøy for å auditere:
- token-oppsett (Maskinporten/Azure AD),
- partner-endepunkter,
- NAV-endepunkter.

Brukes sammen med en JSON-config som beskriver miljø, partnere og NAV-API-er.
\"\"\"

import argparse
import json
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
import requests



@dataclass
class MaskinportenConfig:
    client_id: str
    issuer: str
    token_endpoint: str
    audience: str
    scopes: List[str]
    private_key_path: str
    key_id: Optional[str]


@dataclass
class AzureAdConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    token_endpoint: str
    scopes: List[str]


@dataclass
class EndpointCheck:
    path: str
    method: str
    expected_status: int
    max_response_ms: Optional[float]


@dataclass
class ServiceConfig:
    name: str
    base_url: str
    health_path: Optional[str]
    endpoints: List[EndpointCheck]


@dataclass
class EnvironmentConfig:
    name: str
    maskinporten: Optional[MaskinportenConfig]
    azure_ad: Optional[AzureAdConfig]
    partners: Dict[str, ServiceConfig]
    nav_apis: Dict[str, ServiceConfig]


@dataclass
class OnboardingConfig:
    default_env: str
    environments: Dict[str, EnvironmentConfig]



def _load_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"Fant ikke config-fil: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_config(path: Path) -> OnboardingConfig:
    raw = _load_json(path)
    default_env = raw.get("default_env")
    envs_raw = raw.get("environments")
    if not isinstance(envs_raw, dict) or not envs_raw:
        raise ValueError("Config må inneholde 'environments' som ikke-tomt objekt")

    envs: Dict[str, EnvironmentConfig] = {}
    for env_name, env_val in envs_raw.items():
        mp_raw = env_val.get("maskinporten") or {}
        mp_cfg: Optional[MaskinportenConfig] = None
        if mp_raw:
            mp_cfg = MaskinportenConfig(
                client_id=str(mp_raw.get("client_id", "")).strip(),
                issuer=str(mp_raw.get("issuer", "")).strip(),
                token_endpoint=str(mp_raw.get("token_endpoint", "")).strip(),
                audience=str(mp_raw.get("audience", "")).strip(),
                scopes=[str(s).strip() for s in (mp_raw.get("scopes") or [])],
                private_key_path=str(mp_raw.get("private_key_path", "")).strip(),
                key_id=str(mp_raw.get("key_id")) if mp_raw.get("key_id") is not None else None,
            )

        az_raw = env_val.get("azure_ad") or {}
        az_cfg: Optional[AzureAdConfig] = None
        if az_raw:
            az_cfg = AzureAdConfig(
                tenant_id=str(az_raw.get("tenant_id", "")).strip(),
                client_id=str(az_raw.get("client_id", "")).strip(),
                client_secret=str(az_raw.get("client_secret", "")).strip(),
                token_endpoint=str(az_raw.get("token_endpoint", "")).strip(),
                scopes=[str(s).strip() for s in (az_raw.get("scopes") or [])],
            )

        partners_raw = env_val.get("partners") or {}
        if not isinstance(partners_raw, dict):
            raise ValueError(f"'partners' må være objekt i miljø '{env_name}'")
        partners: Dict[str, ServiceConfig] = {}
        for name, p_val in partners_raw.items():
            base_url = str(p_val.get("base_url", "")).rstrip("/")
            health_path = p_val.get("health_path")
            eps_raw = p_val.get("test_endpoints") or []
            endpoints: List[EndpointCheck] = []
            for e in eps_raw:
                endpoints.append(
                    EndpointCheck(
                        path=str(e.get("path", "/")),
                        method=str(e.get("method", "GET")).upper(),
                        expected_status=int(e.get("expected_status", 200)),
                        max_response_ms=float(e["max_response_ms"]) if e.get("max_response_ms") is not None else None,
                    )
                )
            partners[name] = ServiceConfig(
                name=name,
                base_url=base_url,
                health_path=str(health_path) if health_path is not None else None,
                endpoints=endpoints,
            )

        nav_raw = env_val.get("nav_apis") or {}
        if not isinstance(nav_raw, dict):
            raise ValueError(f"'nav_apis' må være objekt i miljø '{env_name}'")
        nav_apis: Dict[str, ServiceConfig] = {}
        for name, p_val in nav_raw.items():
            base_url = str(p_val.get("base_url", "")).rstrip("/")
            health_path = p_val.get("health_path")
            eps_raw = p_val.get("test_endpoints") or []
            endpoints: List[EndpointCheck] = []
            for e in eps_raw:
                endpoints.append(
                    EndpointCheck(
                        path=str(e.get("path", "/")),
                        method=str(e.get("method", "GET")).upper(),
                        expected_status=int(e.get("expected_status", 200)),
                        max_response_ms=float(e["max_response_ms"]) if e.get("max_response_ms") is not None else None,
                    )
                )
            nav_apis[name] = ServiceConfig(
                name=name,
                base_url=base_url,
                health_path=str(health_path) if health_path is not None else None,
                endpoints=endpoints,
            )

        envs[env_name] = EnvironmentConfig(
            name=env_name,
            maskinporten=mp_cfg,
            azure_ad=az_cfg,
            partners=partners,
            nav_apis=nav_apis,
        )

    if not default_env:
        default_env = next(iter(envs.keys()))
    return OnboardingConfig(default_env=str(default_env), environments=envs)



def _load_private_key(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"Fant ikke privat nøkkel-fil: {path}")
    return path.read_text(encoding="utf-8")



def _build_maskinporten_assertion(mp: MaskinportenConfig) -> str:
    now = int(time.time())
    payload = {
        "iss": mp.issuer or mp.client_id,
        "sub": mp.client_id,
        "aud": mp.audience or mp.token_endpoint,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    headers = {"alg": "RS256", "typ": "JWT"}
    if mp.key_id:
        headers["kid"] = mp.key_id
    private_key = _load_private_key(Path(mp.private_key_path))
    assertion = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    if isinstance(assertion, bytes):
        assertion = assertion.decode("utf-8")
    return assertion



def _request_maskinporten_token(mp: MaskinportenConfig) -> Dict[str, Any]:
    if not mp.client_id or not mp.token_endpoint:
        raise ValueError("Maskinporten-config mangler client_id eller token_endpoint")

    assertion = _build_maskinporten_assertion(mp)
    data = {
        "grant_type": "client_credentials",
        "scope": " ".join(mp.scopes),
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    resp = requests.post(mp.token_endpoint, data=data, timeout=15)
    resp.raise_for_status()
    token_data = resp.json()
    if "access_token" not in token_data:
        raise RuntimeError(f"Mangler 'access_token' i Maskinporten-respons: {token_data}")
    return token_data


def _request_azure_token(az: AzureAdConfig) -> Dict[str, Any]:
    if not az.client_id or not az.client_secret or not az.token_endpoint:
        raise ValueError("Azure AD-config mangler client_id, client_secret eller token_endpoint")
    data = {
        "grant_type": "client_credentials",
        "client_id": az.client_id,
        "client_secret": az.client_secret,
        "scope": " ".join(az.scopes),
    }
    resp = requests.post(az.token_endpoint, data=data, timeout=15)
    resp.raise_for_status()
    token_data = resp.json()
    if "access_token" not in token_data:
        raise RuntimeError(f"Mangler 'access_token' i Azure-respons: {token_data}")
    return token_data



def cmd_tokens(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    env_name = args.env or cfg.default_env
    env = cfg.environments.get(env_name)
    if env is None:
        print(f"Ukjent miljø: {env_name}", file=sys.stderr)
        return 1

    results = []
    all_ok = True

    if env.maskinporten:
        start = time.perf_counter()
        try:
            mp_data = _request_maskinporten_token(env.maskinporten)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            results.append(
                {
                    "type": "maskinporten",
                    "ok": True,
                    "elapsed_ms": elapsed_ms,
                    "token_type": mp_data.get("token_type"),
                    "expires_in": mp_data.get("expires_in"),
                    "scope": mp_data.get("scope"),
                }
            )
            print(f"[OK] Maskinporten-token hentet på {elapsed_ms:.1f} ms")
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            results.append(
                {
                    "type": "maskinporten",
                    "ok": False,
                    "elapsed_ms": elapsed_ms,
                    "error": str(e),
                }
            )
            all_ok = False
            print(f"[FAIL] Maskinporten-token feilet: {e}", file=sys.stderr)
    else:
        print("Maskinporten-config ikke satt for dette miljøet.")

    if env.azure_ad:
        start = time.perf_counter()
        try:
            az_data = _request_azure_token(env.azure_ad)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            results.append(
                {
                    "type": "azure_ad",
                    "ok": True,
                    "elapsed_ms": elapsed_ms,
                    "token_type": az_data.get("token_type"),
                    "expires_in": az_data.get("expires_in"),
                }
            )
            print(f"[OK] Azure AD-token hentet på {elapsed_ms:.1f} ms")
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            results.append(
                {
                    "type": "azure_ad",
                    "ok": False,
                    "elapsed_ms": elapsed_ms,
                    "error": str(e),
                }
            )
            all_ok = False
            print(f"[FAIL] Azure AD-token feilet: {e}", file=sys.stderr)
    else:
        print("Azure AD-config ikke satt for dette miljøet.")

    summary = {
        "env": env.name,
        "total": len(results),
        "passed": sum(1 for r in results if r.get("ok")),
        "failed": sum(1 for r in results if not r.get("ok")),
    }
    report = {"summary": summary, "results": results}

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Token-rapport skrevet til {out_path}")

    return 0 if all_ok else 1



def _audit_service(env_name: str, service_type: str, svc: ServiceConfig, token: Optional[str]):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    checks = []
    all_ok = True

    if svc.health_path:
        url = svc.base_url.rstrip("/") + "/" + svc.health_path.lstrip("/")
        start = time.perf_counter()
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            ok = resp.status_code == 200
            checks.append(
                {
                    "kind": "health",
                    "url": url,
                    "method": "GET",
                    "expected_status": 200,
                    "status_code": resp.status_code,
                    "response_ms": elapsed_ms,
                    "ok": ok,
                }
            )
            if ok:
                print(f"[OK] {service_type} {svc.name} health -> 200 ({elapsed_ms:.1f} ms)")
            else:
                print(
                    f"[FAIL] {service_type} {svc.name} health forventet 200, fikk {resp.status_code}",
                    file=sys.stderr,
                )
                all_ok = False
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            checks.append(
                {
                    "kind": "health",
                    "url": url,
                    "method": "GET",
                    "expected_status": 200,
                    "status_code": None,
                    "response_ms": elapsed_ms,
                    "ok": False,
                    "error": str(e),
                }
            )
            all_ok = False
            print(f"[ERROR] {service_type} {svc.name} health feilet: {e}", file=sys.stderr)

    for ep in svc.endpoints:
        url = svc.base_url.rstrip("/") + "/" + ep.path.lstrip("/")
        start = time.perf_counter()
        try:
            if ep.method == "GET":
                resp = requests.get(url, headers=headers, timeout=15)
            elif ep.method == "POST":
                resp = requests.post(url, headers=headers, json=None, timeout=15)
            else:
                raise ValueError(f"Ustøttet metode: {ep.method}")
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            ok_status = resp.status_code == ep.expected_status
            ok_time = True
            if ep.max_response_ms is not None:
                ok_time = elapsed_ms <= ep.max_response_ms
            ok = ok_status and ok_time
            checks.append(
                {
                    "kind": "endpoint",
                    "url": url,
                    "method": ep.method,
                    "expected_status": ep.expected_status,
                    "status_code": resp.status_code,
                    "response_ms": elapsed_ms,
                    "max_response_ms": ep.max_response_ms,
                    "ok_status": ok_status,
                    "ok_time": ok_time,
                    "ok": ok,
                }
            )
            if ok:
                print(f"[OK] {service_type} {svc.name} {ep.method} {url} -> {resp.status_code} ({elapsed_ms:.1f} ms)")
            else:
                all_ok = False
                print(
                    f"[FAIL] {service_type} {svc.name} {ep.method} {url} -> {resp.status_code} ({elapsed_ms:.1f} ms)",
                    file=sys.stderr,
                )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            checks.append(
                {
                    "kind": "endpoint",
                    "url": url,
                    "method": ep.method,
                    "expected_status": ep.expected_status,
                    "status_code": None,
                    "response_ms": elapsed_ms,
                    "max_response_ms": ep.max_response_ms,
                    "ok_status": False,
                    "ok_time": False,
                    "ok": False,
                    "error": str(e),
                }
            )
            all_ok = False
            print(f"[ERROR] {service_type} {svc.name} {ep.method} {url} feilet: {e}", file=sys.stderr)

    summary = {
        "env": env_name,
        "service_type": service_type,
        "service_name": svc.name,
        "total": len(checks),
        "passed": sum(1 for c in checks if c.get("ok")),
        "failed": sum(1 for c in checks if not c.get("ok")),
    }
    return {"summary": summary, "checks": checks, "ok": all_ok}



def _get_token_for_env(env: EnvironmentConfig, prefer: Optional[str]) -> Optional[str]:
    auth = (prefer or "").lower()
    token_data: Optional[Dict[str, Any]] = None

    if auth in ("maskinporten", "", None) and env.maskinporten:
        token_data = _request_maskinporten_token(env.maskinporten)
    elif auth in ("azure_ad", "azure", "aad") and env.azure_ad:
        token_data = _request_azure_token(env.azure_ad)
    else:
        return None

    return str(token_data["access_token"])



def cmd_partner(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    env_name = args.env or cfg.default_env
    env = cfg.environments.get(env_name)
    if env is None:
        print(f"Ukjent miljø: {env_name}", file=sys.stderr)
        return 1

    svc = env.partners.get(args.name)
    if svc is None:
        print(f"Ukjent partner '{args.name}' i miljø '{env.name}'", file=sys.stderr)
        return 1

    token: Optional[str] = None
    if args.with_token:
        try:
            token = _get_token_for_env(env, args.auth)
        except Exception as e:
            print(f"Feil ved henting av token: {e}", file=sys.stderr)
            return 1

    result = _audit_service(env.name, "partner", svc, token)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Partner-rapport skrevet til {out_path}")

    return 0 if result["ok"] else 1



def cmd_nav(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    env_name = args.env or cfg.default_env
    env = cfg.environments.get(env_name)
    if env is None:
        print(f"Ukjent miljø: {env_name}", file=sys.stderr)
        return 1

    svc = env.nav_apis.get(args.name)
    if svc is None:
        print(f"Ukjent NAV-API '{args.name}' i miljø '{env.name}'", file=sys.stderr)
        return 1

    token: Optional[str] = None
    if args.with_token:
        try:
            token = _get_token_for_env(env, args.auth)
        except Exception as e:
            print(f"Feil ved henting av token: {e}", file=sys.stderr)
            return 1

    result = _audit_service(env.name, "nav_api", svc, token)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"NAV-rapport skrevet til {out_path}")

    return 0 if result["ok"] else 1



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NAV Integration Onboarding Auditor – tokens, partner og NAV-audits."
    )
    parser.add_argument(
        "--config",
        default="onboarding.config.json",
        help="Sti til config-fil (JSON). Default onboarding.config.json.",
    )
    parser.add_argument(
        "--env",
        help="Miljønavn som brukes (overstyrer default_env i config).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_tokens = sub.add_parser("tokens", help="Audit av token-oppsett (Maskinporten/Azure AD).")
    p_tokens.add_argument(
        "--output",
        help="Valgfri sti for å skrive JSON-rapport.",
    )
    p_tokens.set_defaults(func=cmd_tokens)

    p_partner = sub.add_parser("partner", help="Audit av partner-endepunkter.")
    p_partner.add_argument(
        "--name",
        required=True,
        help="Navn på partner slik den er definert i config.",
    )
    p_partner.add_argument(
        "--with-token",
        action="store_true",
        help="Hent token og bruk Authorization-header i kallene.",
    )
    p_partner.add_argument(
        "--auth",
        choices=["maskinporten", "azure_ad"],
        help="Foretrukket auth-type når token skal hentes.",
    )
    p_partner.add_argument(
        "--output",
        help="Valgfri sti for å skrive JSON-rapport.",
    )
    p_partner.set_defaults(func=cmd_partner)

    p_nav = sub.add_parser("nav", help="Audit av NAV-API-endepunkter.")
    p_nav.add_argument(
        "--name",
        required=True,
        help="Navn på NAV-API slik det er definert i config.",
    )
    p_nav.add_argument(
        "--with-token",
        action="store_true",
        help="Hent token og bruk Authorization-header i kallene.",
    )
    p_nav.add_argument(
        "--auth",
        choices=["maskinporten", "azure_ad"],
        help="Foretrukket auth-type når token skal hentes.",
    )
    p_nav.add_argument(
        "--output",
        help="Valgfri sti for å skrive JSON-rapport.",
    )
    p_nav.set_defaults(func=cmd_nav)

    return parser



def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    exit_code = func(args)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
