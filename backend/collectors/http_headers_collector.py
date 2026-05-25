"""http_headers_collector.py — HTTP 보안 응답 헤더 점검 유틸 모듈

SKT T-Markov 평가 가이드(2026-05-22) §5 네트워크/애플리케이션 Pillar 대응.
가이드가 손으로 `Access-Control-Allow-Origin: *` 를 발견했듯이, 같은 검사를
Readyz-T 자동 수집이 그대로 잡아내기 위한 모듈.

이 모듈은 자체적으로 `collect_*` 함수를 노출하지 않는다(자동 autodiscover 대상 아님).
대신 nmap_collector 의 기존 TLS 함수들(collect_tls_services / collect_tls_advanced)이
점수 산정 시 `assess_target` 결과를 raw_json 에 첨부하고 평가에 반영한다.

이 설계 이유:
  - xlsx 체크리스트 매핑(자동 212항목 1:1)을 깨지 않기 위해.
  - HTTP 보안 헤더 검사는 외부 도메인에 대한 비침해 GET 1회로 끝나므로 별도 wrapper
    가 필요 없다(nmap-wrapper 같은 컨테이너 추가 없이 backend 프로세스에서 직접 호출).
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

import httpx


# 네트워크 환경에 의존성 — 외부 도메인 GET에 충분히 빠른 timeout.
_DEFAULT_TIMEOUT = 6.0

# 평가 가중치 — 합 1.0. 부재/약점 비율로 점수 산정.
_HEADER_WEIGHTS = {
    "hsts":               0.20,  # Strict-Transport-Security
    "csp":                0.20,  # Content-Security-Policy
    "x_frame_options":    0.12,  # 클릭재킹 방지
    "x_content_type":     0.08,  # MIME sniff 방지
    "referrer_policy":    0.08,
    "permissions_policy": 0.07,
    "cors_safe":          0.15,  # Access-Control-Allow-Origin != "*" (가이드 §5 명시)
    "info_disclosure":    0.10,  # Server / X-Powered-By 정보 노출 회피
}

_CIDR_RE = re.compile(r"/\d{1,2}$")


def _coerce_to_url(target: str) -> Optional[str]:
    """nmap 형식 target(도메인/IP/CIDR/URL)을 HTTP(S) URL로 변환.

    CIDR(`/24` 등) 는 헤더 검사 대상이 될 수 없으므로 None 반환.
    스킴이 없으면 https 우선.
    """
    if not target:
        return None
    t = target.strip()
    if not t:
        return None
    # CIDR 형식이면 헤더 검사 부적합
    if _CIDR_RE.search(t):
        return None
    if t.startswith("http://") or t.startswith("https://"):
        return t
    return f"https://{t}"


def fetch_security_headers(target: str, timeout: float = _DEFAULT_TIMEOUT) -> dict:
    """target(URL/도메인/IP) 에 단일 GET 요청을 보내 응답 헤더를 수집.

    네트워크 오류·CIDR 같은 비대상 입력은 graceful하게 빈 결과 반환.
    호출 측은 `result["error"]` 로 실패 여부 판단.
    """
    url = _coerce_to_url(target)
    if url is None:
        return {
            "url": None, "status": None, "headers": {},
            "error": "non-URL target (CIDR/empty) — header check skipped",
        }

    try:
        # follow_redirects: HTTPS 강제 리다이렉트 추적해 최종 응답 헤더 분석.
        resp = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Readyz-T/1.0 (zt-assessment header probe)"},
        )
        # 헤더는 case-insensitive — 그대로 dict 화하면서 키 소문자 정규화.
        norm = {k.lower(): v for k, v in resp.headers.items()}
        return {
            "url": str(resp.url),
            "status": resp.status_code,
            "headers": norm,
            "error": None,
        }
    except httpx.RequestError as exc:
        return {
            "url": url, "status": None, "headers": {},
            "error": f"{type(exc).__name__}: {exc}",
        }
    except Exception as exc:  # pragma: no cover — 방어적
        return {
            "url": url, "status": None, "headers": {},
            "error": f"unexpected: {type(exc).__name__}: {exc}",
        }


def assess_headers(headers: dict) -> dict:
    """헤더 dict(소문자 키 정규화) 을 받아 8개 항목 평가 결과를 돌려준다.

    반환: {assessment: {key: pass|warn|fail}, issues: [str...], score: 0.0~1.0,
           findings: {hsts: str, csp: str, ...}}
    score 는 _HEADER_WEIGHTS 기반 가중합. 1.0 = 모두 pass.
    """
    h = headers or {}
    assessment: dict[str, str] = {}
    findings: dict[str, str] = {}
    issues: list[str] = []

    # HSTS — 존재 + max-age >= 31536000(1년) 권장
    hsts = h.get("strict-transport-security", "").strip()
    findings["hsts"] = hsts
    if not hsts:
        assessment["hsts"] = "fail"
        issues.append("HSTS(Strict-Transport-Security) 헤더 누락 — 다운그레이드 공격 노출")
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(m.group(1)) if m else 0
        if max_age >= 31_536_000:
            assessment["hsts"] = "pass"
        else:
            assessment["hsts"] = "warn"
            issues.append(f"HSTS max-age={max_age} (권장 31536000 이상)")

    # CSP — 존재만으로 pass, 누락은 fail
    csp = h.get("content-security-policy", "").strip()
    findings["csp"] = csp[:200]
    if csp:
        assessment["csp"] = "pass"
    else:
        assessment["csp"] = "fail"
        issues.append("Content-Security-Policy 헤더 누락 — XSS 위험 노출 면적 증가")

    # X-Frame-Options — DENY/SAMEORIGIN
    xfo = h.get("x-frame-options", "").strip().upper()
    findings["x_frame_options"] = xfo
    if xfo in ("DENY", "SAMEORIGIN"):
        assessment["x_frame_options"] = "pass"
    elif xfo:
        assessment["x_frame_options"] = "warn"
        issues.append(f"X-Frame-Options={xfo} (DENY/SAMEORIGIN 권장)")
    else:
        # CSP frame-ancestors 가 있으면 우회 인정
        if "frame-ancestors" in csp.lower():
            assessment["x_frame_options"] = "pass"
        else:
            assessment["x_frame_options"] = "fail"
            issues.append("X-Frame-Options 누락 + CSP frame-ancestors 없음 — 클릭재킹 노출")

    # X-Content-Type-Options — nosniff
    xcto = h.get("x-content-type-options", "").strip().lower()
    findings["x_content_type"] = xcto
    if xcto == "nosniff":
        assessment["x_content_type"] = "pass"
    else:
        assessment["x_content_type"] = "fail"
        issues.append("X-Content-Type-Options: nosniff 누락 — MIME sniff 공격 가능")

    # Referrer-Policy
    rp = h.get("referrer-policy", "").strip().lower()
    findings["referrer_policy"] = rp
    if rp:
        assessment["referrer_policy"] = "pass"
    else:
        assessment["referrer_policy"] = "warn"
        issues.append("Referrer-Policy 누락 — 외부 referer 로 내부 경로 유출 가능")

    # Permissions-Policy (구 Feature-Policy)
    pp = h.get("permissions-policy") or h.get("feature-policy") or ""
    findings["permissions_policy"] = pp.strip()[:200]
    if pp:
        assessment["permissions_policy"] = "pass"
    else:
        assessment["permissions_policy"] = "warn"

    # CORS — Access-Control-Allow-Origin: *  ←  가이드 §5 명시 케이스
    cors = h.get("access-control-allow-origin", "").strip()
    findings["cors_origin"] = cors
    if not cors:
        # CORS 헤더 자체 부재 = 동일 출처 정책 유지 = 안전
        assessment["cors_safe"] = "pass"
    elif cors == "*":
        assessment["cors_safe"] = "fail"
        issues.append(
            "Access-Control-Allow-Origin: * — 모든 출처에서 cross-origin 요청 허용. "
            "인증이 필요한 API 와 결합되면 자격 노출 위험."
        )
    else:
        assessment["cors_safe"] = "pass"

    # 정보 노출 — Server / X-Powered-By 가 버전 정보 포함하면 warn
    server = h.get("server", "").strip()
    powered = h.get("x-powered-by", "").strip()
    findings["server"] = server
    findings["x_powered_by"] = powered
    leak_signals = []
    if server and re.search(r"\d+\.\d+", server):
        leak_signals.append(f"Server={server}")
    if powered:
        leak_signals.append(f"X-Powered-By={powered}")
    if leak_signals:
        assessment["info_disclosure"] = "warn"
        issues.append("서버/스택 정보 노출: " + ", ".join(leak_signals))
    else:
        assessment["info_disclosure"] = "pass"

    # 점수 계산 — pass=1.0, warn=0.5, fail=0.0
    weight_map = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
    score = 0.0
    for key, weight in _HEADER_WEIGHTS.items():
        verdict = assessment.get(key, "fail")
        score += weight_map[verdict] * weight

    return {
        "assessment": assessment,
        "findings":   findings,
        "issues":     issues,
        "score":      round(score, 3),
    }


def assess_target(target: str, timeout: float = _DEFAULT_TIMEOUT) -> dict:
    """target 에 GET → 헤더 평가를 한 번에 수행.

    반환 dict: {url, status, headers, error, assessment, findings, issues, score}
    error 가 None 아니면 평가 결과는 모든 항목 fail/score=0.0.
    """
    fetched = fetch_security_headers(target, timeout=timeout)
    if fetched.get("error"):
        return {
            **fetched,
            "assessment": {},
            "findings": {},
            "issues": [f"헤더 수집 실패: {fetched['error']}"],
            "score": 0.0,
        }
    assessed = assess_headers(fetched["headers"])
    return {**fetched, **assessed}
