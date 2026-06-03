"""vercel_collector.py — Vercel API 기반 진단 모듈.

Vercel-deployed 시스템(T-Markov frontend 등)에서 환경변수 분리, 팀 RBAC,
배포 이력, 도메인 SSL 등을 자동 점검한다.

자격: Personal/Team API Token (Bearer). NewAssessment Step 3 에서 사용자가 입력.
세션 단위 주입: set_session_creds({"token": "vcp_...", "team_id": "...", "project_id": "..."})

매핑은 기존 web_probe/Trivy 항목과 다중 매핑(증거 보강). assessment.py 의
_resolve_supported_tools 가 tool_scope.vercel=True 일 때 활성화한다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import os

import httpx

CollectedResult = dict

VERCEL_TOKEN     = os.environ.get("VERCEL_TOKEN", "")
VERCEL_TEAM_ID   = os.environ.get("VERCEL_TEAM_ID", "")
VERCEL_PROJECT_ID = os.environ.get("VERCEL_PROJECT_ID", "")

_TIMEOUT = 8.0
API_BASE = "https://api.vercel.com"

_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    global _session_creds
    _session_creds = creds or None


def _get_token() -> str:
    if _session_creds and _session_creds.get("token"):
        return str(_session_creds["token"]).strip()
    return VERCEL_TOKEN


def _get_team_id() -> str:
    if _session_creds and _session_creds.get("team_id"):
        return str(_session_creds["team_id"]).strip()
    return VERCEL_TEAM_ID


def _get_project_id() -> str:
    if _session_creds and _session_creds.get("project_id"):
        return str(_session_creds["project_id"]).strip()
    return VERCEL_PROJECT_ID


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(item_id: str, maturity: str, metric_key: str, metric_value: float,
            threshold: float, verdict: str, raw: dict,
            error: Optional[str] = None) -> CollectedResult:
    return {
        "item_id": item_id,
        "maturity": maturity,
        "tool": "vercel",
        "result": verdict,
        "metric_key": metric_key,
        "metric_value": float(metric_value),
        "threshold": float(threshold),
        "raw_json": raw,
        "collected_at": _now_iso(),
        "error": error,
    }


def _unavailable(item_id: str, maturity: str, metric_key: str, threshold: float,
                 error_msg: str, raw: Optional[dict] = None) -> CollectedResult:
    return _result(item_id, maturity, metric_key, 0.0, threshold,
                   "평가불가", raw or {}, error_msg)


def _api_get(path: str, params: Optional[dict] = None,
             timeout: float = _TIMEOUT) -> tuple[Any, Optional[str]]:
    token = _get_token()
    if not token:
        return None, "Vercel API token 미설정"
    p = dict(params or {})
    team = _get_team_id()
    if team:
        p.setdefault("teamId", team)
    try:
        resp = httpx.get(
            f"{API_BASE}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=p,
            timeout=timeout,
        )
        if resp.status_code in (401, 403):
            return None, f"권한 부족: HTTP {resp.status_code}"
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        return resp.json(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Collector functions
# ─────────────────────────────────────────────────────────────────────────────


def collect_deployment_history(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.2_2: 최근 배포 성공률 ≥ 0.9 → 충족 (안전한 애플리케이션 배포)."""
    MK, TH = "deployment_success_ratio", 0.9
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    data, err = _api_get("/v6/deployments", params={"projectId": proj, "limit": 20})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    deps = (data or {}).get("deployments") or []
    if not deps:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"count": 0})
    ready = sum(1 for d in deps if (d.get("state") or d.get("readyState")) == "READY")
    ratio = ready / len(deps)
    verdict = "충족" if ratio >= TH else "부분충족" if ratio >= 0.5 else "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total": len(deps), "ready": ready})


def collect_env_separation(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.3_2: 환경별(production/preview/development) env var 분리 ≥ 2 환경 사용."""
    MK, TH = "env_targets_used", 2.0
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    data, err = _api_get(f"/v9/projects/{proj}/env", params={"decrypt": "false"})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    envs = (data or {}).get("envs") or []
    targets: set = set()
    for e in envs:
        for t in (e.get("target") or []):
            targets.add(t)
    count = float(len(targets))
    verdict = "충족" if count >= TH else "부분충족" if count == 1 else "미충족"
    # 값은 마스킹하고 키 이름만 raw 에 보존
    keys = [e.get("key") for e in envs if e.get("key")]
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"targets": sorted(targets), "env_keys": keys[:50]})


def collect_team_rbac(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.4_2: 팀 멤버 역할 분포 — owner 비율 ≤ 0.5 → 충족 (최소권한)."""
    MK, TH = "non_owner_ratio", 0.5
    team = _get_team_id()
    if not team:
        return _unavailable(item_id, maturity, MK, TH, "team_id 미설정 — 개인 계정은 평가불가")
    data, err = _api_get(f"/v2/teams/{team}/members")
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    members = (data or {}).get("members") or []
    if not members:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"members": 0})
    owners = sum(1 for m in members if (m.get("role") or "").lower() == "owner")
    ratio = 1.0 - (owners / len(members))
    verdict = "충족" if ratio >= TH else "부분충족" if ratio > 0 else "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total": len(members), "owners": owners})


def collect_domain_ssl(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.1_3: 프로젝트 도메인의 HTTPS 강제(verified+ssl 활성) 비율 ≥ 0.9 → 충족."""
    MK, TH = "https_enforced_ratio", 0.9
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    data, err = _api_get(f"/v9/projects/{proj}/domains")
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    domains = (data or {}).get("domains") or []
    if not domains:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"domains": 0})
    verified = sum(1 for d in domains if d.get("verified"))
    ratio = verified / len(domains)
    verdict = "충족" if ratio >= TH else "부분충족" if ratio >= 0.5 else "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total": len(domains), "verified": verified,
                    "names": [d.get("name") for d in domains][:10]})


def collect_secrets_management(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.2_3: 시크릿 env var 의 type=encrypted 비율 ≥ 0.9 → SBOM/시크릿 관리 흔적."""
    MK, TH = "encrypted_env_ratio", 0.9
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    data, err = _api_get(f"/v9/projects/{proj}/env")
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    envs = (data or {}).get("envs") or []
    if not envs:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"envs": 0})
    encrypted = sum(1 for e in envs if (e.get("type") or "").lower() in ("encrypted", "secret"))
    ratio = encrypted / len(envs)
    verdict = "충족" if ratio >= TH else "부분충족" if ratio >= 0.5 else "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total_envs": len(envs), "encrypted": encrypted})


def collect_audit_log_retention(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.1_2: 팀 audit log 조회 가능 + 최근 30일 활동 ≥ 1 → 보안 이벤트 자동 기록 흔적."""
    MK, TH = "recent_audit_events", 1.0
    team = _get_team_id()
    if not team:
        return _unavailable(item_id, maturity, MK, TH, "team_id 미설정 (audit log는 팀 plan만)")
    # Vercel audit log endpoint (Pro+)
    data, err = _api_get(f"/v1/teams/{team}/audit-logs", params={"limit": 30})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    events = (data or {}).get("entries") or (data or {}).get("auditLogs") or []
    count = float(len(events))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict, {"events": len(events)})


# ─────────────────────────────────────────────────────────────────────────────
# 확장 collector (2026-06) — Firewall/배포 보호(SSO·비밀번호·Trusted IP) 점검 추가.
# docstring item_id 로 autodiscover 자동 편입. 측정 실패 → 평가불가.
# ─────────────────────────────────────────────────────────────────────────────


def collect_firewall_threat_response(item_id: str, maturity: str) -> CollectedResult:
    """3.2.1.1_1: 위협 대응 — Vercel Firewall 활성 + 룰 ≥ 1 → 충족, 활성만 → 부분충족."""
    MK, TH = "firewall_rules_active", 1.0
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    data, err = _api_get("/v1/security/firewall/config", params={"projectId": proj})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    d = data or {}
    enabled = bool(d.get("firewallEnabled") or d.get("enabled")
                   or d.get("managedRules") or d.get("crs"))
    custom = d.get("rules") if isinstance(d.get("rules"), list) else []
    managed = d.get("managedRules") if isinstance(d.get("managedRules"), dict) else {}
    rule_count = len(custom) + len(managed)
    if enabled and rule_count >= 1:
        verdict, val = "충족", float(rule_count)
    elif enabled:
        verdict, val = "부분충족", 0.5
    else:
        verdict, val = "미충족", 0.0
    return _result(item_id, maturity, MK, val, TH, verdict,
                   {"firewall_enabled": enabled, "rule_count": rule_count})


def _deployment_protection_count(proj: str) -> tuple[int, dict, Optional[str]]:
    """프로젝트의 배포 보호 정책 수(SSO/비밀번호/Trusted IP) 산출."""
    data, err = _api_get(f"/v9/projects/{proj}")
    if err:
        return 0, {}, err
    d = data or {}
    tip = d.get("trustedIps")
    detail = {
        "sso":         bool(d.get("ssoProtection")),
        "password":    bool(d.get("passwordProtection")),
        "trusted_ips": bool(tip and (not isinstance(tip, dict) or tip.get("addresses"))),
    }
    return sum(1 for v in detail.values() if v), detail, None


def collect_deployment_protection(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: 접근통제 — 배포 보호(SSO/비밀번호/Trusted IP) 정책 ≥ 1 → 충족."""
    MK, TH = "deployment_protection_policies", 1.0
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    count, detail, err = _deployment_protection_count(proj)
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    verdict = "충족" if count >= 1 else "미충족"
    return _result(item_id, maturity, MK, float(count), TH, verdict, detail)


def collect_app_inventory(item_id: str, maturity: str) -> CollectedResult:
    """5.4.2.1_1: 애플리케이션 인벤토리 — Vercel 배포 프로젝트(앱) 목록 ≥ 1 → 충족.

    수동→자동 재분류: 배포된 프로젝트 목록 자체가 살아있는 앱 인벤토리.
    """
    MK, TH = "app_inventory_count", 1.0
    data, err = _api_get("/v9/projects", params={"limit": 100})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    projects = (data or {}).get("projects") or []
    count = float(len(projects))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"project_count": len(projects),
                    "names": [p.get("name") for p in projects][:20]})


def collect_remote_access_protection(item_id: str, maturity: str) -> CollectedResult:
    """5.3.1.1_2: 원격 접속 — 배포 환경 접근 보호(SSO/비밀번호/Trusted IP) 정책 ≥ 1 → 충족."""
    MK, TH = "remote_access_policies", 1.0
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    count, detail, err = _deployment_protection_count(proj)
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    verdict = "충족" if count >= 1 else "미충족"
    return _result(item_id, maturity, MK, float(count), TH, verdict, detail)
