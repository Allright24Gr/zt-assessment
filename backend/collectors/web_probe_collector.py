"""
web_probe_collector.py — 외부 도구 무관 자동 측정 (OIDC / DNS / HTTP / TLS / CT log)

설계 의도
─────────
IdP·SIEM 제품 종류(Keycloak/Wazuh/Google Workspace/SaaS-only 등)에 관계없이
공개 도메인 하나만 있으면 외부에서 측정 가능한 보안 통제를 자동 진단한다.
T-Markov(Google Workspace + Vercel + Railway, SIEM 없음) 같은 SaaS-only 환경에서도
nmap/trivy 외 추가로 자동 진단 항목을 늘리는 것이 목표다.

5 영역:
  1) OIDC Discovery  — /.well-known/openid-configuration 노출/grant types/PKCE/jwks
  2) DNS Hygiene     — SPF / DMARC / DKIM / CAA (Cloudflare DoH 사용)
  3) HTTP Headers    — HSTS / CSP / XFO / CORS / 정보 노출 (http_headers_collector 재사용)
  4) TLS Scanner     — 인증서 만료/key 강도/체인 + TLS 버전 (ssl + cryptography)
  5) CT Log          — crt.sh 발급 인증서 수/SAN 다양성/wildcard 비율

각 collector 함수는 인자 없이 호출되며(set_session_target 으로 도메인 주입),
실패 시 _err() 로 평가불가, 성공 시 _ok() 로 충족/부분충족/미충족 dict 반환.
docstring 첫 줄 `<item_id>: ...` 패턴으로 dispatcher autodiscover.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import http_headers_collector as _hh
from . import web_evidence_collector as _we


CollectedResult = dict
TOOL = "web_probe"

# ─── 세션 단위 target 주입 ───────────────────────────────────────────────────
# 도메인 또는 URL (예: "tmarkovframework.vercel.app" / "https://example.com")
WEB_PROBE_TARGET = os.getenv("WEB_PROBE_TARGET", "")
_current_target: Optional[str] = None

# 동일 세션 내 다수 collector 가 같은 도메인을 두 번 조회하지 않도록 lightweight memo.
# _run_collectors 가 새 세션마다 set_session_target() 호출 → _reset_cache() 로 비움.
_cache: dict = {}


def set_session_target(target: Optional[str]) -> None:
    """세션별 web_probe 대상(도메인/URL)을 주입(또는 None으로 해제)."""
    global _current_target
    _current_target = (target or None)
    _cache.clear()


def _get_target() -> str:
    return _current_target or WEB_PROBE_TARGET or ""


def _get_domain() -> str:
    """도메인 부분만 추출 (URL 이면 hostname)."""
    t = (_get_target() or "").strip()
    if not t:
        return ""
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split("/")[0].split(":")[0]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── 결과 dict 헬퍼 ──────────────────────────────────────────────────────────

def _ok(item_id: str, maturity: str, result: str, metric_key: str,
        metric_value: float, threshold: float, raw: dict) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": TOOL,
        "result": result, "metric_key": metric_key, "metric_value": float(metric_value),
        "threshold": float(threshold), "raw_json": raw, "collected_at": _now_iso(),
        "error": None,
    }


def _err(item_id: str, maturity: str, metric_key: str, threshold: float,
         error: str, raw: dict | None = None) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": TOOL,
        "result": "평가불가", "metric_key": metric_key, "metric_value": 0.0,
        "threshold": float(threshold), "raw_json": raw or {}, "collected_at": _now_iso(),
        "error": error,
    }


def _no_target_err(item_id: str, maturity: str, metric_key: str, threshold: float) -> CollectedResult:
    return _err(item_id, maturity, metric_key, threshold,
                "web_probe target(도메인/URL) 미지정", {})


# ──────────────────────────────────────────────────────────────────────────────
# 캐시된 외부 호출 — 한 세션에서 도메인당 1회만 실제 호출.
# ──────────────────────────────────────────────────────────────────────────────

def _cached_headers(domain: str) -> dict:
    k = f"headers:{domain}"
    if k not in _cache:
        _cache[k] = _hh.assess_target(domain)
    return _cache[k]


def _cached_dns(domain: str) -> dict:
    k = f"dns:{domain}"
    if k not in _cache:
        _cache[k] = _we.assess_dns_security(domain)
    return _cache[k]


def _cached_tls(domain: str) -> dict:
    k = f"tls:{domain}"
    if k not in _cache:
        _cache[k] = _we.assess_tls_certificate(domain)
    return _cache[k]


def _cached_oidc(domain: str, timeout: float = 6.0) -> dict:
    """OpenID Connect Discovery 조회. 표준 경로 두 개 시도."""
    k = f"oidc:{domain}"
    if k in _cache:
        return _cache[k]
    paths = (
        "/.well-known/openid-configuration",
        "/.well-known/openid_configuration",
    )
    base = f"https://{domain}".rstrip("/")
    out: dict = {"domain": domain, "discovered": False, "endpoint": None, "config": {}, "error": None}
    for p in paths:
        url = base + p
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True,
                          headers={"User-Agent": "Readyz-T/1.0 web-probe-oidc"})
            if r.status_code == 200:
                try:
                    cfg = r.json()
                except Exception:
                    continue
                if isinstance(cfg, dict) and (cfg.get("issuer") or cfg.get("authorization_endpoint")):
                    out["discovered"] = True
                    out["endpoint"] = url
                    out["config"] = cfg
                    break
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
    _cache[k] = out
    return out


def _cached_ct(domain: str, timeout: float = 10.0) -> dict:
    """crt.sh Certificate Transparency 조회. 발급 이력 + SAN 통계."""
    k = f"ct:{domain}"
    if k in _cache:
        return _cache[k]
    out: dict = {
        "domain": domain, "cert_count": 0, "wildcard_count": 0,
        "issuers": [], "sample": [], "error": None,
    }
    try:
        r = httpx.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "Readyz-T/1.0 ct-probe"},
        )
        if r.status_code != 200:
            out["error"] = f"crt.sh HTTP {r.status_code}"
            _cache[k] = out
            return out
        # crt.sh 가 비표준 JSON(라인 단위)을 돌려주는 경우 있음 → 둘 다 처리.
        text = r.text.strip()
        if not text:
            _cache[k] = out
            return out
        try:
            entries = r.json()
            if not isinstance(entries, list):
                entries = []
        except Exception:
            entries = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line or line in ("[", "]"):
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        entries.append(obj)
                except Exception:
                    continue
        out["cert_count"] = len(entries)
        issuers: dict[str, int] = {}
        wild = 0
        for e in entries:
            iname = (e.get("issuer_name") or "")[:120]
            if iname:
                issuers[iname] = issuers.get(iname, 0) + 1
            cn = (e.get("common_name") or "") + " " + (e.get("name_value") or "")
            if "*" in cn:
                wild += 1
        out["wildcard_count"] = wild
        out["issuers"] = sorted(issuers.items(), key=lambda kv: -kv[1])[:8]
        out["sample"] = entries[:3]
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    _cache[k] = out
    return out


# ──────────────────────────────────────────────────────────────────────────────
# 1) OIDC Discovery 기반 collector (5개)
# ──────────────────────────────────────────────────────────────────────────────

def collect_oidc_idp_integration() -> CollectedResult:
    """1.1.2.3_1: OIDC Discovery 노출 + issuer/authorization_endpoint 존재 → ID 통합 관리(IdP federation) 흔적

    충족: discovery 200 + issuer 존재
    미충족: discovery 미노출 (외부 IdP 통합 미확인)
    """
    item_id, maturity = "1.1.2.3_1", "향상"
    MK, TH = "oidc_discovery_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    oidc = _cached_oidc(dom)
    if oidc.get("error") and not oidc.get("discovered"):
        # 미발견은 평가 결과(미충족) 로 처리, 진짜 네트워크 에러만 평가불가.
        if "Name or service not known" in str(oidc.get("error")) or "timeout" in str(oidc.get("error")).lower():
            return _err(item_id, maturity, MK, TH, oidc["error"], oidc)
    discovered = bool(oidc.get("discovered"))
    cfg = oidc.get("config") or {}
    has_issuer = bool(cfg.get("issuer"))
    value = 1.0 if (discovered and has_issuer) else 0.0
    result = "충족" if value >= TH else "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, oidc)


def collect_oidc_global_federation() -> CollectedResult:
    """1.1.2.4_1: OIDC scopes_supported 에 openid+profile+email → 글로벌 표준 ID 연계 솔루션 적용

    충족: openid+profile+email 모두 지원
    부분충족: openid 만
    미충족: discovery 미노출
    """
    item_id, maturity = "1.1.2.4_1", "최적화"
    MK, TH = "global_oidc_scopes_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    oidc = _cached_oidc(dom)
    cfg = oidc.get("config") or {}
    scopes = set(cfg.get("scopes_supported") or [])
    required = {"openid", "profile", "email"}
    if scopes >= required:
        value, result = 1.0, "충족"
    elif "openid" in scopes:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, {"scopes": sorted(scopes), **oidc})


def collect_oidc_context_auth() -> CollectedResult:
    """1.2.1.3_2: OIDC acr_values_supported / claims_supported(amr,acr) → 컨텍스트(MFA·디바이스) 인증

    충족: acr_values_supported 존재 OR claims_supported 에 amr/acr
    부분충족: code_challenge_methods_supported 에 S256 만 (PKCE)
    미충족: 위 모두 없음
    """
    item_id, maturity = "1.2.1.3_2", "향상"
    MK, TH = "oidc_context_signals", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    oidc = _cached_oidc(dom)
    cfg = oidc.get("config") or {}
    acr_vals = cfg.get("acr_values_supported") or []
    claims = set(cfg.get("claims_supported") or [])
    pkce = set(cfg.get("code_challenge_methods_supported") or [])
    has_acr = bool(acr_vals) or bool(claims & {"acr", "amr"})
    has_pkce = "S256" in pkce
    if has_acr:
        value, result = 1.0, "충족"
    elif has_pkce:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {"acr_values": acr_vals, "claims": sorted(claims), "pkce": sorted(pkce), **oidc})


def collect_oidc_credential_endpoint() -> CollectedResult:
    """4.2.2.1_1: OIDC token_endpoint + jwks_uri → 자격 증명 중앙 발급/회전 인프라

    충족: token_endpoint + jwks_uri 둘 다 존재 (자동 회전 가능)
    부분충족: 한 쪽만
    미충족: 양쪽 모두 미노출 → 자격 증명 수동 관리 추정
    """
    item_id, maturity = "4.2.2.1_1", "기존"
    MK, TH = "oidc_token_and_jwks", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    oidc = _cached_oidc(dom)
    cfg = oidc.get("config") or {}
    has_token = bool(cfg.get("token_endpoint"))
    has_jwks = bool(cfg.get("jwks_uri"))
    if has_token and has_jwks:
        value, result = 1.0, "충족"
    elif has_token or has_jwks:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {"token_endpoint": cfg.get("token_endpoint"), "jwks_uri": cfg.get("jwks_uri"), **oidc})


def collect_oidc_authz_endpoint() -> CollectedResult:
    """5.1.1.1_1: OIDC authorization_endpoint 존재 → 리소스 권한 부여 중앙 통합(SSO) 흔적

    충족: authorization_endpoint 존재
    미충족: 미노출 (권한 부여 수동 관리 추정)
    """
    item_id, maturity = "5.1.1.1_1", "기존"
    MK, TH = "oidc_authz_endpoint_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    oidc = _cached_oidc(dom)
    cfg = oidc.get("config") or {}
    has_authz = bool(cfg.get("authorization_endpoint"))
    value = 1.0 if has_authz else 0.0
    result = "충족" if has_authz else "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {"authorization_endpoint": cfg.get("authorization_endpoint"), **oidc})


# ──────────────────────────────────────────────────────────────────────────────
# 2) DNS Hygiene (3개) — 메일/도메인 보안 통제
# ──────────────────────────────────────────────────────────────────────────────

def collect_dns_dmarc_policy() -> CollectedResult:
    """6.5.1.1_1: DMARC 정책 (p=reject/quarantine) → DLP 정책 수립 + 자동 평가 흔적

    충족: p=reject
    부분충족: p=quarantine
    미충족: p=none 또는 DMARC 없음
    """
    item_id, maturity = "6.5.1.1_1", "기존"
    MK, TH = "dmarc_enforcement_strength", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    dns = _cached_dns(dom)
    dmarc = (dns.get("dmarc") or {})
    verdict = dmarc.get("verdict", "fail")
    if verdict == "pass":
        value, result = 1.0, "충족"
    elif verdict == "warn":
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, dns)


def collect_dns_spf_coverage() -> CollectedResult:
    """6.5.1.1_2: SPF 레코드 + -all/~all 강제 → DLP 범위(메일 도메인) 보호 흔적

    충족: SPF + -all
    부분충족: SPF + ~all 또는 ?all
    미충족: SPF 없음
    """
    item_id, maturity = "6.5.1.1_2", "기존"
    MK, TH = "spf_policy_strength", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    dns = _cached_dns(dom)
    spf_obj = (dns.get("spf") or {})
    verdict = spf_obj.get("verdict", "fail")
    spf_val = spf_obj.get("value", "")
    if verdict == "pass" and " -all" in spf_val:
        value, result = 1.0, "충족"
    elif spf_val:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, dns)


def collect_dns_dmarc_reporting() -> CollectedResult:
    """6.5.2.1_2: DMARC rua= 보고 주소 존재 → 메일 활동 모니터링 프로세스 수립 흔적

    충족: DMARC + rua= 보고 주소
    부분충족: DMARC 만 (보고 주소 없음)
    미충족: DMARC 자체 없음
    """
    item_id, maturity = "6.5.2.1_2", "기존"
    MK, TH = "dmarc_rua_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    dns = _cached_dns(dom)
    dmarc = (dns.get("dmarc") or {})
    dmarc_val = dmarc.get("value", "")
    has_rua = "rua=" in dmarc_val.lower()
    if has_rua:
        value, result = 1.0, "충족"
    elif dmarc_val:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {"has_rua": has_rua, "dmarc_value": dmarc_val, **dns})


# ──────────────────────────────────────────────────────────────────────────────
# 3) HTTP Security Headers (9개) — 정책/접근제어 흔적
# ──────────────────────────────────────────────────────────────────────────────

def collect_http_access_control_policy() -> CollectedResult:
    """4.1.1.1_1: HTTP 보안 헤더 종합 점수 >= 0.7 → 자동화된 접근 통제 정책 적용 흔적

    충족: score >= 0.7 (HSTS+CSP+XFO+CORS 등 다수 적용)
    부분충족: 0.4 ~ 0.7
    미충족: < 0.4
    """
    item_id, maturity = "4.1.1.1_1", "기존"
    MK, TH = "http_header_security_score", 0.7
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    score = float(h.get("score", 0.0))
    if score >= TH:
        result = "충족"
    elif score >= 0.4:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, MK, score, TH, h)


def collect_http_authz_consistency() -> CollectedResult:
    """4.1.1.1_3: HTTP 응답에 CSP 또는 X-Frame-Options 존재 → 권한 정책 자동 강제 흔적

    충족: CSP pass 또는 XFO pass
    부분충족: 둘 중 warn
    미충족: 둘 다 fail
    """
    item_id, maturity = "4.1.1.1_3", "기존"
    MK, TH = "authz_header_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    a = h.get("assessment") or {}
    csp_v = a.get("csp", "fail")
    xfo_v = a.get("x_frame_options", "fail")
    if csp_v == "pass" or xfo_v == "pass":
        value, result = 1.0, "충족"
    elif csp_v == "warn" or xfo_v == "warn":
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, h)


def collect_http_policy_consistency() -> CollectedResult:
    """4.4.1.1_2: HSTS + X-Content-Type-Options + Referrer-Policy 동시 적용 → 시스템 보안 정책 일관 관리

    충족: 3개 모두 pass
    부분충족: 1~2개 pass
    미충족: 모두 fail
    """
    item_id, maturity = "4.4.1.1_2", "기존"
    MK, TH = "system_policy_header_count", 3.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    a = h.get("assessment") or {}
    passes = sum(1 for k in ("hsts", "x_content_type", "referrer_policy") if a.get(k) == "pass")
    value = float(passes)
    if passes >= 3:
        result = "충족"
    elif passes >= 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, h)


def collect_http_monitoring_signal() -> CollectedResult:
    """5.2.1.1_1: 응답 헤더에 Server/X-Powered-By 정보 노출 최소화 → 자동 보안 상태 모니터링 흔적

    충족: 정보 노출 pass (서버/스택 정보 노출 없음)
    부분충족: warn (Server 헤더 정도)
    미충족: fail (X-Powered-By 등 자세한 노출)
    """
    item_id, maturity = "5.2.1.1_1", "기존"
    MK, TH = "info_disclosure_safe", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    a = h.get("assessment") or {}
    v = a.get("info_disclosure", "fail")
    if v == "pass":
        value, result = 1.0, "충족"
    elif v == "warn":
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, h)


def collect_http_event_recording_signal() -> CollectedResult:
    """5.2.1.1_2: Permissions-Policy + CSP 보고(report-uri/report-to) → 보안 이벤트 자동 기록 흔적

    충족: CSP 에 report-uri/report-to 또는 Permissions-Policy 적용
    부분충족: Permissions-Policy 만 적용
    미충족: 둘 다 없음
    """
    item_id, maturity = "5.2.1.1_2", "기존"
    MK, TH = "event_reporting_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    findings = h.get("findings") or {}
    csp = (findings.get("csp") or "").lower()
    pp = (findings.get("permissions_policy") or "").strip()
    has_report = ("report-uri" in csp) or ("report-to" in csp)
    if has_report:
        value, result = 1.0, "충족"
    elif pp:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, h)


def collect_http_data_access_policy() -> CollectedResult:
    """6.2.1.1_1: CORS Access-Control-Allow-Origin 정책 적정성 → 데이터 접근 정책 자동 강제

    충족: CORS 헤더 없음 OR 명시적 출처 (안전)
    미충족: Access-Control-Allow-Origin: *
    """
    item_id, maturity = "6.2.1.1_1", "기존"
    MK, TH = "cors_policy_safe", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    a = h.get("assessment") or {}
    v = a.get("cors_safe", "fail")
    value = 1.0 if v == "pass" else 0.0
    result = "충족" if value >= TH else "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, h)


def collect_http_data_access_authentication() -> CollectedResult:
    """6.2.1.1_2: 응답에 Set-Cookie Secure+HttpOnly+SameSite → 데이터 접근권한 자동 강제

    충족: 모든 쿠키가 Secure+HttpOnly 동시 적용
    부분충족: 일부만 / SameSite 만 있음
    미충족: 쿠키 있는데 Secure 없음 OR Set-Cookie 자체 없음(자동 정책 흔적 부재)
    """
    item_id, maturity = "6.2.1.1_2", "기존"
    MK, TH = "secure_cookie_ratio", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    # raw_response 가 없어서 헤더 dict 에서 Set-Cookie 패턴을 추출.
    raw_headers = h.get("headers") or {}
    set_cookies = raw_headers.get("set-cookie", "")
    if not set_cookies:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH,
                   {**h, "note": "Set-Cookie 헤더 없음 — 쿠키 기반 인증 미사용 또는 비공개 페이지"})
    cookies_lower = set_cookies.lower()
    cookie_count = max(cookies_lower.count("="), 1)
    secure_hits = cookies_lower.count("secure")
    httponly_hits = cookies_lower.count("httponly")
    samesite_hits = cookies_lower.count("samesite")
    # 단순 비율: (secure + httponly) / (2 * cookie_count)
    safe_score = (secure_hits + httponly_hits) / (2 * cookie_count)
    if safe_score >= 0.9 and samesite_hits > 0:
        value, result = 1.0, "충족"
    elif safe_score >= 0.5:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {**h, "secure_score": safe_score, "cookie_count": cookie_count})


def collect_http_data_labeling() -> CollectedResult:
    """6.4.1.1_1: X-Content-Type-Options: nosniff → MIME 타입(데이터 형식 라벨) 강제 지침 수립

    충족: nosniff pass
    미충족: nosniff 누락
    """
    item_id, maturity = "6.4.1.1_1", "기존"
    MK, TH = "nosniff_present", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    a = h.get("assessment") or {}
    value = 1.0 if a.get("x_content_type") == "pass" else 0.0
    result = "충족" if value >= TH else "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, h)


def collect_http_consistent_classification() -> CollectedResult:
    """6.4.1.1_2: Content-Type + X-Content-Type-Options + CSP 동시 적용 → 일관된 데이터 분류 체계

    충족: 3개 시그널 모두 pass (Content-Type 헤더 + nosniff + CSP)
    부분충족: 1~2개
    미충족: 모두 없음
    """
    item_id, maturity = "6.4.1.1_2", "기존"
    MK, TH = "classification_signal_count", 3.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    if h.get("error"):
        return _err(item_id, maturity, MK, TH, h["error"], h)
    raw_headers = h.get("headers") or {}
    a = h.get("assessment") or {}
    has_ct = bool(raw_headers.get("content-type"))
    has_nosniff = (a.get("x_content_type") == "pass")
    has_csp = (a.get("csp") == "pass")
    passes = sum([has_ct, has_nosniff, has_csp])
    value = float(passes)
    if passes >= 3:
        result = "충족"
    elif passes >= 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {**h, "content_type": raw_headers.get("content-type")})


# ──────────────────────────────────────────────────────────────────────────────
# 4) TLS Scanner (4개) — 암호화/키 관리
# ──────────────────────────────────────────────────────────────────────────────

def _probe_tls_version(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """TLS 1.3 / 1.2 / 1.1 / 1.0 각 버전을 ssl.PROTOCOL_*  로 시도.

    반환: {tls13: bool, tls12: bool, tls11: bool, tls10: bool, error}
    Python 3.10+ 의 ssl 모듈은 TLSv1/1.1 PROTOCOL 상수가 deprecated 일 수 있어
    OP_NO_TLSv* 비활성으로 강제 협상 시도 → 성공/실패 기록.
    """
    out = {"tls13": False, "tls12": False, "tls11": False, "tls10": False, "error": None}
    versions = [
        ("tls13", ssl.TLSVersion.TLSv1_3),
        ("tls12", ssl.TLSVersion.TLSv1_2),
        ("tls11", ssl.TLSVersion.TLSv1_1),
        ("tls10", ssl.TLSVersion.TLSv1),
    ]
    for label, ver in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            # 자체 서명 인증서까지 허용 — 우리는 negotiation 가능성만 확인.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    _ = ssock.version()
                    out[label] = True
        except (ssl.SSLError, OSError, ValueError):
            out[label] = False
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _cached_tls_versions(domain: str) -> dict:
    k = f"tls_ver:{domain}"
    if k not in _cache:
        _cache[k] = _probe_tls_version(domain)
    return _cache[k]


def collect_tls_modern_cipher() -> CollectedResult:
    """3.3.1.4_1: TLS 1.3 협상 가능 → 최신 암호화 기술 도입

    충족: TLS 1.3 ok + TLS 1.0/1.1 거부
    부분충족: TLS 1.2 까지만 (TLS 1.3 미협상)
    미충족: TLS 1.0/1.1 활성
    """
    item_id, maturity = "3.3.1.4_1", "최적화"
    MK, TH = "tls13_only_modern", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    ver = _cached_tls_versions(dom)
    legacy = ver.get("tls10") or ver.get("tls11")
    if ver.get("tls13") and not legacy:
        value, result = 1.0, "충족"
    elif ver.get("tls12") and not legacy:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, ver)


def collect_tls_key_management() -> CollectedResult:
    """3.3.1.4_2: TLS 인증서 key 강도 (RSA ≥ 2048 or ECDSA) + CAA 레코드 → 통합 키 관리

    충족: key 강도 충분 + CAA 존재 (CA 발급 제한)
    부분충족: 둘 중 하나만
    미충족: 둘 다 미충족
    """
    item_id, maturity = "3.3.1.4_2", "최적화"
    MK, TH = "key_mgmt_strength", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    tls = _cached_tls(dom)
    dns = _cached_dns(dom)
    if tls.get("error"):
        return _err(item_id, maturity, MK, TH, tls["error"], {"tls": tls, "dns": dns})
    key_type = tls.get("key_type", "")
    key_bits = int(tls.get("key_bits") or 0)
    key_strong = (key_type == "RSA" and key_bits >= 2048) or (key_type == "ECDSA")
    caa_verdict = (dns.get("caa") or {}).get("verdict", "fail")
    caa_present = (caa_verdict == "pass")
    if key_strong and caa_present:
        value, result = 1.0, "충족"
    elif key_strong or caa_present:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {"tls": tls, "dns_caa": dns.get("caa")})


def collect_tls_encryption_policy() -> CollectedResult:
    """6.3.1.1_2: HSTS 헤더 + TLS 인증서 유효 → 데이터 암호화 정책 (전송 구간) 자동 강제

    충족: HSTS pass + 인증서 유효 (>30일 남음)
    부분충족: 한쪽만
    미충족: 둘 다 미충족
    """
    item_id, maturity = "6.3.1.1_2", "기존"
    MK, TH = "encryption_policy_score", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    h = _cached_headers(dom)
    tls = _cached_tls(dom)
    hsts_pass = ((h.get("assessment") or {}).get("hsts") == "pass")
    cert_pass = (tls.get("verdict") == "pass")
    if hsts_pass and cert_pass:
        value, result = 1.0, "충족"
    elif hsts_pass or cert_pass:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {"hsts_verdict": (h.get("assessment") or {}).get("hsts"),
                "tls": tls})


def collect_tls_initial_authority() -> CollectedResult:
    """6.3.1.1_3: TLS 인증서 발급자 신뢰성 (Let's Encrypt/Google/DigiCert 등 공인 CA) → 초기 권한 관리 체계

    충족: 공인 CA 발급 + 30일 이상 유효
    부분충족: 공인 CA 발급 + 30일 미만
    미충족: 자체 서명 또는 만료
    """
    item_id, maturity = "6.3.1.1_3", "기존"
    MK, TH = "trusted_ca_cert", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    tls = _cached_tls(dom)
    if tls.get("error"):
        return _err(item_id, maturity, MK, TH, tls["error"], tls)
    issuer = (tls.get("issuer") or "").lower()
    days = int(tls.get("days_remaining") or 0)
    trusted_ca_keywords = ("let's encrypt", "letsencrypt", "digicert", "google", "amazon",
                           "cloudflare", "sectigo", "globalsign", "comodo", "geotrust")
    is_public_ca = any(k in issuer for k in trusted_ca_keywords)
    if is_public_ca and days >= 30:
        value, result = 1.0, "충족"
    elif is_public_ca:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, tls)


# ──────────────────────────────────────────────────────────────────────────────
# 5) CT Log (crt.sh) 기반 collector (3개)
# ──────────────────────────────────────────────────────────────────────────────

def collect_ct_secure_deployment() -> CollectedResult:
    """5.4.1.1_2: CT 로그에 도메인 인증서 1건 이상 존재 → 공인 발급 절차 운영(초기 배포 보안 절차)

    충족: 인증서 1건 이상 + wildcard 비율 < 50%
    부분충족: 인증서 있지만 wildcard 비율 >= 50% (광범위 발급)
    미충족: CT 로그에 발견 없음 (자체 서명 또는 미공인 발급)
    """
    item_id, maturity = "5.4.1.1_2", "기존"
    MK, TH = "ct_cert_count", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    ct = _cached_ct(dom)
    if ct.get("error") and ct.get("cert_count", 0) == 0:
        return _err(item_id, maturity, MK, TH, ct["error"], ct)
    count = int(ct.get("cert_count") or 0)
    wild = int(ct.get("wildcard_count") or 0)
    wild_ratio = (wild / count) if count else 0.0
    if count >= 1 and wild_ratio < 0.5:
        value, result = float(count), "충족"
    elif count >= 1:
        value, result = float(count), "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH, ct)


def collect_ct_app_inventory_signal() -> CollectedResult:
    """5.4.2.1_2: CT 로그 SAN 다양성 (서로 다른 서브도메인 1+ 발견) → 애플리케이션 기본 정보 외부 자동 식별

    충족: 발급 인증서 5건 이상 (활발한 ops 흔적)
    부분충족: 1~4건
    미충족: CT 로그 미발견
    """
    item_id, maturity = "5.4.2.1_2", "기존"
    MK, TH = "ct_active_issuance", 5.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    ct = _cached_ct(dom)
    if ct.get("error") and ct.get("cert_count", 0) == 0:
        return _err(item_id, maturity, MK, TH, ct["error"], ct)
    count = float(ct.get("cert_count") or 0)
    if count >= TH:
        result = "충족"
    elif count >= 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, MK, count, TH, ct)


def collect_ct_dev_segregation() -> CollectedResult:
    """5.5.1.4_1: CT 로그 발급자 분포 (단일 CA 집중도 < 0.9) → 개발/운영 발급 권한 격리 흔적

    충족: 최상위 발급자 점유 < 0.9 (다양화)
    부분충족: 단일 CA 100% 집중 (단순 단일 CA 사용)
    미충족: CT 로그 미발견 (외부 검증 불가)
    """
    item_id, maturity = "5.5.1.4_1", "최적화"
    MK, TH = "issuer_diversity", 1.0
    dom = _get_domain()
    if not dom:
        return _no_target_err(item_id, maturity, MK, TH)
    ct = _cached_ct(dom)
    if ct.get("error") and ct.get("cert_count", 0) == 0:
        return _err(item_id, maturity, MK, TH, ct["error"], ct)
    count = int(ct.get("cert_count") or 0)
    issuers = ct.get("issuers") or []  # [(name, n), ...]
    if count == 0 or not issuers:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH, ct)
    top_share = issuers[0][1] / count if count else 1.0
    if top_share < 0.9:
        value, result = 1.0, "충족"
    elif count >= 2:
        value, result = 0.5, "부분충족"
    else:
        value, result = 0.0, "미충족"
    return _ok(item_id, maturity, result, MK, value, TH,
               {**ct, "top_issuer_share": round(top_share, 3)})
