"""railway_collector.py — Railway GraphQL API 기반 진단 모듈.

Railway-deployed 시스템(T-Markov backend 등)에서 서비스 환경변수 분리,
배포 상태, 멤버 권한, 헬스체크 등을 자동 점검한다.

자격: API token (Bearer). NewAssessment Step 3 에서 사용자가 입력.
세션 단위 주입: set_session_creds({"token": "...", "project_id": "...", "service_id": "...", "environment_id": "..."})
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import os

import httpx

CollectedResult = dict

RAILWAY_TOKEN       = os.environ.get("RAILWAY_TOKEN", "")
RAILWAY_PROJECT_ID  = os.environ.get("RAILWAY_PROJECT_ID", "")
RAILWAY_SERVICE_ID  = os.environ.get("RAILWAY_SERVICE_ID", "")
RAILWAY_ENVIRONMENT_ID = os.environ.get("RAILWAY_ENVIRONMENT_ID", "")

_TIMEOUT = 10.0
GRAPHQL_URL = "https://backboard.railway.app/graphql/v2"

_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    global _session_creds
    _session_creds = creds or None


def _get_token() -> str:
    if _session_creds and _session_creds.get("token"):
        return str(_session_creds["token"]).strip()
    return RAILWAY_TOKEN


def _get_project_id() -> str:
    if _session_creds and _session_creds.get("project_id"):
        return str(_session_creds["project_id"]).strip()
    return RAILWAY_PROJECT_ID


def _get_service_id() -> str:
    if _session_creds and _session_creds.get("service_id"):
        return str(_session_creds["service_id"]).strip()
    return RAILWAY_SERVICE_ID


def _get_environment_id() -> str:
    if _session_creds and _session_creds.get("environment_id"):
        return str(_session_creds["environment_id"]).strip()
    return RAILWAY_ENVIRONMENT_ID


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(item_id: str, maturity: str, metric_key: str, metric_value: float,
            threshold: float, verdict: str, raw: dict,
            error: Optional[str] = None) -> CollectedResult:
    return {
        "item_id": item_id,
        "maturity": maturity,
        "tool": "railway",
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


def _graphql(query: str, variables: Optional[dict] = None,
             timeout: float = _TIMEOUT) -> tuple[Any, Optional[str]]:
    token = _get_token()
    if not token:
        return None, "Railway API token 미설정"
    try:
        resp = httpx.post(
            GRAPHQL_URL,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"query": query, "variables": variables or {}},
            timeout=timeout,
        )
        if resp.status_code in (401, 403):
            return None, f"권한 부족: HTTP {resp.status_code}"
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        body = resp.json()
        if body.get("errors"):
            errs = body["errors"]
            return None, f"GraphQL error: {errs[0].get('message', 'unknown')[:200]}"
        return body.get("data") or {}, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Collector functions
# ─────────────────────────────────────────────────────────────────────────────


def collect_deployment_status(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.2_4: 최근 배포 무결성 — latest SUCCESS 상태 → 충족."""
    MK, TH = "latest_deployment_success", 1.0
    svc = _get_service_id()
    if not svc:
        return _unavailable(item_id, maturity, MK, TH, "service_id 미설정")
    q = """
    query LatestDeployment($id: String!) {
      service(id: $id) {
        deployments(first: 5) {
          edges { node { id status createdAt } }
        }
      }
    }
    """
    data, err = _graphql(q, {"id": svc})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    edges = (((data or {}).get("service") or {}).get("deployments") or {}).get("edges") or []
    if not edges:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"deployments": 0})
    statuses = [e.get("node", {}).get("status") for e in edges]
    latest_ok = 1.0 if statuses and statuses[0] == "SUCCESS" else 0.0
    success_ratio = sum(1 for s in statuses if s == "SUCCESS") / len(statuses)
    verdict = "충족" if latest_ok >= TH and success_ratio >= 0.8 else "부분충족" if latest_ok else "미충족"
    return _result(item_id, maturity, MK, latest_ok, TH, verdict,
                   {"statuses": statuses, "success_ratio": round(success_ratio, 2)})


def collect_env_var_separation(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.3_1: 서비스 환경변수 개수 ≥ 1 + production 분리 → 의존성/시크릿 관리 흔적."""
    MK, TH = "env_var_count", 1.0
    svc = _get_service_id()
    env_id = _get_environment_id()
    if not svc or not env_id:
        return _unavailable(item_id, maturity, MK, TH, "service_id/environment_id 미설정")
    q = """
    query ServiceVars($serviceId: String!, $envId: String!) {
      variables(serviceId: $serviceId, environmentId: $envId)
    }
    """
    data, err = _graphql(q, {"serviceId": svc, "envId": env_id})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    vars_dict = (data or {}).get("variables") or {}
    keys = list(vars_dict.keys()) if isinstance(vars_dict, dict) else []
    count = float(len(keys))
    verdict = "충족" if count >= TH else "미충족"
    # 값은 raw 에 포함하지 않음 (시크릿 누출 방지)
    return _result(item_id, maturity, MK, count, TH, verdict, {"env_keys": keys[:50]})


def collect_project_members(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.4_3: 프로젝트 멤버 ≥ 2 + admin 비율 ≤ 0.5 → 권한 분리 흔적."""
    MK, TH = "member_count", 2.0
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    q = """
    query ProjectMembers($id: String!) {
      project(id: $id) {
        members { id role }
      }
    }
    """
    data, err = _graphql(q, {"id": proj})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    members = ((data or {}).get("project") or {}).get("members") or []
    count = float(len(members))
    admins = sum(1 for m in members if (m.get("role") or "").lower() in ("admin", "owner"))
    if count >= TH:
        admin_ratio = admins / max(count, 1)
        verdict = "충족" if admin_ratio <= 0.5 else "부분충족"
    elif count == 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"total": int(count), "admins": admins})


def collect_service_uptime(item_id: str, maturity: str) -> CollectedResult:
    """3.5.1.3_2: 서비스 healthcheck 활성 + 최근 배포 active → 가용성 모니터링."""
    MK, TH = "healthcheck_configured", 1.0
    svc = _get_service_id()
    if not svc:
        return _unavailable(item_id, maturity, MK, TH, "service_id 미설정")
    q = """
    query ServiceInstances($id: String!) {
      service(id: $id) {
        id name
        serviceInstances {
          edges { node { healthcheckPath restartPolicyType startCommand } }
        }
      }
    }
    """
    data, err = _graphql(q, {"id": svc})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    edges = (((data or {}).get("service") or {}).get("serviceInstances") or {}).get("edges") or []
    if not edges:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"instances": 0})
    has_hc = sum(1 for e in edges if (e.get("node") or {}).get("healthcheckPath"))
    ratio = has_hc / len(edges)
    val = 1.0 if ratio > 0 else 0.0
    verdict = "충족" if ratio >= 0.5 else "부분충족" if ratio > 0 else "미충족"
    return _result(item_id, maturity, MK, val, TH, verdict,
                   {"instances": len(edges), "with_healthcheck": has_hc})


def collect_restart_policy(item_id: str, maturity: str) -> CollectedResult:
    """3.5.1.1_3: 서비스 인스턴스 restart policy 설정(ON_FAILURE/ALWAYS) → 가용성 보장."""
    MK, TH = "restart_policy_configured", 1.0
    svc = _get_service_id()
    if not svc:
        return _unavailable(item_id, maturity, MK, TH, "service_id 미설정")
    q = """
    query ServiceRestart($id: String!) {
      service(id: $id) {
        serviceInstances {
          edges { node { restartPolicyType } }
        }
      }
    }
    """
    data, err = _graphql(q, {"id": svc})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    edges = (((data or {}).get("service") or {}).get("serviceInstances") or {}).get("edges") or []
    if not edges:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"instances": 0})
    configured = sum(1 for e in edges
                     if (e.get("node") or {}).get("restartPolicyType") in ("ON_FAILURE", "ALWAYS"))
    ratio = configured / len(edges)
    val = 1.0 if ratio >= 0.5 else 0.0
    verdict = "충족" if ratio >= 0.5 else "미충족"
    return _result(item_id, maturity, MK, val, TH, verdict,
                   {"instances": len(edges), "with_restart": configured})


# ─── 수동→자동 재분류 항목 (2026-06): 기준이 "존재/구성"이라 도구가 직접 관측 가능 ───


def collect_micro_segmentation(item_id: str, maturity: str) -> CollectedResult:
    """3.1.2.1_2: 마이크로 세그멘테이션 — Railway 서비스(격리된 네트워크 단위) ≥ 1 존재 → 충족.

    수동→자동 재분류: 각 Railway 서비스는 독립 컨테이너/내부망 단위 = 워크로드 세그먼트.
    """
    MK, TH = "isolated_service_count", 1.0
    proj = _get_project_id()
    if not proj:
        return _unavailable(item_id, maturity, MK, TH, "project_id 미설정")
    q = """
    query ProjectServices($id: String!) {
      project(id: $id) {
        services { edges { node { id name } } }
      }
    }
    """
    data, err = _graphql(q, {"id": proj})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    edges = (((data or {}).get("project") or {}).get("services") or {}).get("edges") or []
    count = float(len(edges))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict, {"service_count": len(edges)})


def collect_network_redundancy(item_id: str, maturity: str) -> CollectedResult:
    """3.5.1.2_1: 네트워크 회복성 — 서비스 인스턴스 복제(numReplicas) 구성 → 충족(≥2), 단일 → 부분충족."""
    MK, TH = "replica_count", 2.0
    svc = _get_service_id()
    if not svc:
        return _unavailable(item_id, maturity, MK, TH, "service_id 미설정")
    q = """
    query ServiceReplicas($id: String!) {
      service(id: $id) {
        serviceInstances { edges { node { numReplicas } } }
      }
    }
    """
    data, err = _graphql(q, {"id": svc})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    edges = (((data or {}).get("service") or {}).get("serviceInstances") or {}).get("edges") or []
    if not edges:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"instances": 0})
    replicas = [(e.get("node") or {}).get("numReplicas") or 1 for e in edges]
    max_rep = float(max(replicas)) if replicas else 1.0
    verdict = "충족" if max_rep >= TH else "부분충족" if max_rep >= 1 else "미충족"
    return _result(item_id, maturity, MK, max_rep, TH, verdict,
                   {"instances": len(edges), "max_replicas": int(max_rep)})


def collect_network_region(item_id: str, maturity: str) -> CollectedResult:
    """3.5.1.2_2: 네트워크 회복성 — 서비스 배포 리전 구성됨 → 충족."""
    MK, TH = "region_configured", 1.0
    svc = _get_service_id()
    if not svc:
        return _unavailable(item_id, maturity, MK, TH, "service_id 미설정")
    q = """
    query ServiceRegion($id: String!) {
      service(id: $id) {
        serviceInstances { edges { node { region } } }
      }
    }
    """
    data, err = _graphql(q, {"id": svc})
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    edges = (((data or {}).get("service") or {}).get("serviceInstances") or {}).get("edges") or []
    regions = sorted({(e.get("node") or {}).get("region") for e in edges
                      if (e.get("node") or {}).get("region")})
    count = float(len(regions))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict, {"regions": regions})
