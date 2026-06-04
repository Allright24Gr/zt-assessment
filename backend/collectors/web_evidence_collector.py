"""web_evidence_collector.py — 공개 URL 기반 외부 자동 점검 (양식 비고 자동 채움용)

SKT T-Markov 평가 가이드 §5 대응 — 사용자가 수동 진단 양식을 채울 때 *판단 근거*
찾는 시간을 줄이기 위해, 공개 URL 만으로 확인 가능한 사실들을 자동 수집한다.

이 모듈은 점수에 직접 반영되지 않는다(autodiscover 대상 아님). 결과는
manual.py 의 _build_session_template_xlsx 가 양식의 비고 컬럼 / 부록 시트에
미리 채워서 사용자에게 노출한다.

수집 영역:
  1) HTTP 응답 헤더 (HSTS/CSP/CORS/XFO 등)  — http_headers_collector 재사용
  2) DNS 보안 레코드 (SPF/DMARC/DKIM/CAA)   — Cloudflare DoH API
  3) TLS 인증서                              — ssl + cryptography 표준 라이브러리
  4) 공개 노출 점검 (security.txt/robots.txt/.well-known/) — httpx
  5) GitHub repo 분석 (Dockerfile/lockfile/CI workflow)   — GitHub REST API
"""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from . import http_headers_collector as _hh


_TIMEOUT = 6.0
_GITHUB_REPO_RE = re.compile(r"^(?:https?://github\.com/)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


# ─── 1. DNS 보안 레코드 (Cloudflare DoH) ─────────────────────────────────────

def _doh_query(name: str, rtype: str, timeout: float = _TIMEOUT) -> tuple[list[str], Optional[str]]:
    """Cloudflare 1.1.1.1 DNS-over-HTTPS 조회. 반환 (records, error).

    error 가 None → 조회 성공. 이때 빈 리스트는 '레코드 없음'(정상 측정 결과)이다.
    error 가 set  → 측정 자체 실패(네트워크/타임아웃/비200). 이 경우 빈 리스트를
    '레코드 없음(미충족)'으로 오해하면 안 되고 '평가불가'로 처리해야 한다.
    (이전엔 실패와 부재를 모두 빈 리스트로 삼켜 DNS 측정 실패가 '미충족'으로 오분류됐다)"""
    try:
        resp = httpx.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return [], f"DoH HTTP {resp.status_code}"
        data = resp.json()
        return [a.get("data", "").strip('"') for a in (data.get("Answer") or [])], None
    except Exception as e:
        return [], f"DoH 조회 실패: {type(e).__name__}"


def assess_dns_security(domain: str) -> dict:
    """SPF/DMARC/DKIM(추정)/CAA 조회 결과 + 평가.

    반환: {spf, dmarc, dkim_hint, caa, issues, score}
    score 0.0~1.0 (4개 항목 각 0.25 가중)
    """
    issues: list[str] = []

    # SPF — root domain TXT 중 "v=spf1" 시작 행
    txt, spf_err = _doh_query(domain, "TXT")
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    if spf_err:
        spf_verdict = "error"
        issues.append(f"SPF 조회 실패(DNS 측정 불가): {spf_err}")
    elif spf:
        if " -all" in spf or " ~all" in spf:
            spf_verdict = "pass"
        else:
            spf_verdict = "warn"
            issues.append(f"SPF 정책 약함(?all/+all): {spf[:80]}")
    else:
        spf_verdict = "fail"
        issues.append("SPF 레코드 없음 — 메일 위조 방지 안 됨")

    # DMARC — _dmarc.<domain> TXT
    dmarc_txt, dmarc_err = _doh_query(f"_dmarc.{domain}", "TXT")
    dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), "")
    if dmarc_err:
        dmarc_verdict = "error"
        issues.append(f"DMARC 조회 실패(DNS 측정 불가): {dmarc_err}")
    elif dmarc:
        if "p=reject" in dmarc.lower():
            dmarc_verdict = "pass"
        elif "p=quarantine" in dmarc.lower():
            dmarc_verdict = "warn"
        else:
            dmarc_verdict = "warn"
            issues.append(f"DMARC 정책 p=none — 모니터링만, 차단 안 함")
    else:
        dmarc_verdict = "fail"
        issues.append("DMARC 레코드 없음")

    # DKIM 힌트 — selector 가 도메인마다 달라 직접 찾기 어려움. 흔한 selector 추정.
    dkim_hint = ""
    for sel in ("google", "default", "k1", "mail", "selector1"):
        dq, _ = _doh_query(f"{sel}._domainkey.{domain}", "TXT")
        if dq:
            dkim_hint = f"{sel}._domainkey 발견: {dq[0][:60]}..."
            break

    # CAA — 인증서 발급 권한 제한
    caa, caa_err = _doh_query(domain, "CAA")
    if caa_err:
        caa_verdict = "error"
    elif caa:
        caa_verdict = "pass"
    else:
        caa_verdict = "warn"
        issues.append("CAA 레코드 없음 — 누구나 이 도메인 인증서 발급 가능")

    weight = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "error": 0.0}
    score = round(
        (weight[spf_verdict] + weight[dmarc_verdict] +
         (1.0 if dkim_hint else 0.0) + weight[caa_verdict]) / 4.0,
        3,
    )

    return {
        "domain":      domain,
        "spf":         {"value": spf,   "verdict": spf_verdict,   "query_error": spf_err},
        "dmarc":       {"value": dmarc, "verdict": dmarc_verdict, "query_error": dmarc_err},
        "dkim_hint":   dkim_hint or "(흔한 selector에서 미발견 — 도메인별 selector 별도 확인 필요)",
        "caa":         {"records": caa, "verdict": caa_verdict, "query_error": caa_err},
        "issues":      issues,
        "score":       score,
        # 스코어링 collector 가 '측정 실패→평가불가' 를 판정할 수 있는 통합 신호.
        "dns_query_error": spf_err or dmarc_err,
    }


# ─── 2. TLS 인증서 ────────────────────────────────────────────────────────────

def assess_tls_certificate(domain: str, port: int = 443, timeout: float = _TIMEOUT) -> dict:
    """TLS 인증서 검사 — 발급자, 만료일, key length, SAN.

    반환: {issuer, subject, not_after, days_remaining, key_bits, sans, issues, verdict}
    """
    issues: list[str] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # cryptography 로 DER 파싱 (PEM/x509 모두 호환)
                der = ssock.getpeercert(binary_form=True)
                cert_text = ssock.getpeercert()

        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        cert = x509.load_der_x509_certificate(der)

        # 발급자/주체
        issuer  = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        # 만료일 (timezone-aware)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
                    cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days

        # Key 길이
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            key_bits = pk.key_size
            key_type = "RSA"
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            key_bits = pk.curve.key_size
            key_type = "ECDSA"
        else:
            key_bits = 0
            key_type = type(pk).__name__

        # SAN (Subject Alternative Names)
        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in ext.value]
        except x509.ExtensionNotFound:
            pass

        # 판정
        if days_remaining < 0:
            verdict = "fail"
            issues.append(f"인증서 만료됨 ({days_remaining}일 경과)")
        elif days_remaining < 14:
            verdict = "fail"
            issues.append(f"인증서 만료 임박 ({days_remaining}일 남음)")
        elif days_remaining < 30:
            verdict = "warn"
            issues.append(f"인증서 만료 30일 미만 ({days_remaining}일 남음)")
        else:
            verdict = "pass"

        if key_type == "RSA" and key_bits < 2048:
            issues.append(f"RSA key 길이 {key_bits}bit (2048 이상 권장)")
            if verdict == "pass":
                verdict = "warn"

        return {
            "domain":         domain,
            "issuer":         issuer,
            "subject":        subject,
            "not_after":      not_after.isoformat(),
            "days_remaining": days_remaining,
            "key_type":       key_type,
            "key_bits":       key_bits,
            "sans":           sans[:10],  # 너무 길면 자름
            "issues":         issues,
            "verdict":        verdict,
        }
    except Exception as exc:
        return {
            "domain": domain,
            "error":  f"{type(exc).__name__}: {exc}",
            "issues": [f"TLS 인증서 검사 실패: {exc}"],
            "verdict": "fail",
        }


# ─── 3. 공개 노출 점검 (security.txt / robots.txt / .well-known/) ────────────

_WELL_KNOWN_PATHS = [
    "/security.txt",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/openid-configuration",
    "/.well-known/openid_configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
]


def assess_public_exposure(base_url: str, timeout: float = _TIMEOUT) -> dict:
    """공개 노출된 .well-known/ 디렉터리·robots.txt 등 점검.

    반환: {checked: [{path, status, size, snippet}], summary: str}
    """
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"
    base_url = base_url.rstrip("/")

    checked = []
    has_security = False
    has_robots = False
    for path in _WELL_KNOWN_PATHS:
        try:
            r = httpx.get(
                f"{base_url}{path}",
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "Readyz-T/1.0 web-evidence"},
            )
            entry = {
                "path":    path,
                "status":  r.status_code,
                "size":    len(r.content) if r.content else 0,
            }
            if r.status_code == 200 and r.content:
                # snippet 200자만
                text = r.text[:200] if hasattr(r, "text") else ""
                entry["snippet"] = text
                if "security.txt" in path:
                    has_security = True
                if "robots.txt" in path:
                    has_robots = True
            checked.append(entry)
        except Exception as exc:
            checked.append({"path": path, "error": str(exc)})

    summary_parts = []
    summary_parts.append("✅ security.txt 운영중" if has_security else "❌ security.txt 없음 — 취약점 신고 채널 부재")
    summary_parts.append("✅ robots.txt 운영중" if has_robots else "⚠️ robots.txt 없음")

    return {
        "base_url": base_url,
        "checked":  checked,
        "summary":  " · ".join(summary_parts),
    }


# ─── 4. GitHub repo 분석 ──────────────────────────────────────────────────────

def assess_github_repo(repo_ref: str, timeout: float = _TIMEOUT) -> dict:
    """GitHub repo 의 보안 관련 파일 존재 여부 점검.

    repo_ref: "owner/name" 또는 "https://github.com/owner/name" 모두 허용.
    공개 repo 만 (인증 없이 GitHub REST API 호출).
    """
    m = _GITHUB_REPO_RE.match(repo_ref.strip())
    if not m:
        return {"error": f"GitHub repo 참조 형식 오류: {repo_ref}", "verdict": "fail"}
    owner, name = m.group(1), m.group(2)

    api_base = f"https://api.github.com/repos/{owner}/{name}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Readyz-T/1.0 github-probe",
    }

    # repo 기본 정보
    try:
        meta = httpx.get(api_base, headers=headers, timeout=timeout)
        if meta.status_code != 200:
            return {
                "owner": owner, "name": name,
                "error": f"repo 조회 실패 (HTTP {meta.status_code})",
                "verdict": "fail",
            }
        meta_data = meta.json()
    except Exception as exc:
        return {"owner": owner, "name": name, "error": str(exc), "verdict": "fail"}

    default_branch = meta_data.get("default_branch", "main")

    # 보안 관련 파일 존재 여부 (HEAD 비슷한 효과를 위해 contents API 사용)
    files_to_check = [
        "Dockerfile",
        ".github/workflows",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "go.sum",
        "Cargo.lock",
        "SECURITY.md",
        ".github/dependabot.yml",
        ".github/SECURITY.md",
    ]
    findings: dict[str, bool] = {}
    for path in files_to_check:
        try:
            r = httpx.get(
                f"{api_base}/contents/{path}",
                params={"ref": default_branch},
                headers=headers,
                timeout=timeout,
            )
            findings[path] = (r.status_code == 200)
        except Exception:
            findings[path] = False

    # CI workflow 목록 (디렉터리 조회)
    ci_workflows: list[str] = []
    if findings.get(".github/workflows"):
        try:
            r = httpx.get(
                f"{api_base}/contents/.github/workflows",
                params={"ref": default_branch},
                headers=headers,
                timeout=timeout,
            )
            if r.status_code == 200:
                for f in r.json():
                    if isinstance(f, dict) and f.get("name", "").endswith((".yml", ".yaml")):
                        ci_workflows.append(f["name"])
        except Exception:
            pass

    has_lockfile = any(findings.get(p) for p in
                       ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                        "requirements.txt", "Pipfile.lock", "poetry.lock",
                        "go.sum", "Cargo.lock"))
    has_security_md = findings.get("SECURITY.md") or findings.get(".github/SECURITY.md")
    has_dependabot = findings.get(".github/dependabot.yml")
    has_dockerfile = findings.get("Dockerfile")

    issues = []
    if not has_lockfile:
        issues.append("의존성 lockfile 없음 — 빌드 재현성·SBOM 추적 어려움")
    if not has_security_md:
        issues.append("SECURITY.md 없음 — 보안 취약점 신고 절차 부재")
    if not has_dependabot:
        issues.append(".github/dependabot.yml 없음 — 의존성 자동 업데이트 미설정")
    if not ci_workflows:
        issues.append("CI workflow 없음 — 자동 검증/테스트 부재")

    score = round(
        (int(has_lockfile) * 0.3 + int(bool(has_security_md)) * 0.2 +
         int(bool(has_dependabot)) * 0.2 + int(bool(ci_workflows)) * 0.2 +
         int(has_dockerfile) * 0.1),
        3,
    )

    return {
        "owner":         owner,
        "name":          name,
        "default_branch": default_branch,
        "stars":         meta_data.get("stargazers_count", 0),
        "language":      meta_data.get("language") or "",
        "license":       (meta_data.get("license") or {}).get("spdx_id") or "(없음)",
        "files":         findings,
        "ci_workflows":  ci_workflows,
        "issues":        issues,
        "score":         score,
    }


# ─── 5. 통합 — 양식 비고 채움용 텍스트 생성 ──────────────────────────────────

def collect_public_evidence(
    nmap_target: str = "",
    github_repo: str = "",
    timeout: float = _TIMEOUT,
) -> dict:
    """모든 자동 점검을 한 번에 실행 — manual.py 양식 빌더가 호출.

    nmap_target: 공개 도메인/URL (예: "tmarkovframework.vercel.app")
    github_repo: "owner/name" 또는 GitHub URL

    반환: {http_headers, dns, tls, exposure, github, generated_at}
    각 키는 해당 영역 자동 점검 결과 dict. 실패 영역은 error 키 포함.
    """
    result: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nmap_target":  nmap_target or None,
        "github_repo":  github_repo or None,
    }

    # 도메인 추출 — URL 이든 도메인이든 도메인만 뽑음
    domain = ""
    if nmap_target:
        target_str = nmap_target.strip()
        if "://" in target_str:
            domain = urlparse(target_str).hostname or ""
        else:
            domain = target_str.split("/")[0].split(":")[0]

    if domain:
        # 1) HTTP 헤더 (기존 collector 재사용)
        try:
            result["http_headers"] = _hh.assess_target(domain, timeout=timeout)
        except Exception as exc:
            result["http_headers"] = {"error": str(exc)}

        # 2) DNS
        try:
            result["dns"] = assess_dns_security(domain)
        except Exception as exc:
            result["dns"] = {"error": str(exc)}

        # 3) TLS 인증서
        try:
            result["tls"] = assess_tls_certificate(domain, timeout=timeout)
        except Exception as exc:
            result["tls"] = {"error": str(exc)}

        # 4) 공개 노출
        try:
            result["exposure"] = assess_public_exposure(domain, timeout=timeout)
        except Exception as exc:
            result["exposure"] = {"error": str(exc)}

    # 5) GitHub repo (별도 입력)
    if github_repo:
        try:
            result["github"] = assess_github_repo(github_repo, timeout=timeout)
        except Exception as exc:
            result["github"] = {"error": str(exc)}

    return result


# ─── 6. Pillar 별 사람-친화 요약 생성 (양식 비고용) ──────────────────────────

def summarize_for_pillar(evidence: dict, pillar: str) -> str:
    """수집된 evidence 를 Pillar 별 관련 사실만 추려서 텍스트 한 문단으로.

    manual.py 가 양식의 각 행 비고 칸에 채울 때 호출.
    """
    lines: list[str] = []
    http = evidence.get("http_headers") or {}
    dns  = evidence.get("dns") or {}
    tls  = evidence.get("tls") or {}
    expo = evidence.get("exposure") or {}
    gh   = evidence.get("github") or {}

    p = pillar or ""

    if "신원" in p:
        # OIDC discovery 노출 → IdP 추정
        oidc = next((c for c in (expo.get("checked") or [])
                     if "openid" in c.get("path", "") and c.get("status") == 200), None)
        if oidc:
            lines.append(f"[자동] OpenID Connect discovery 노출 ({oidc['path']}, {oidc.get('size', 0)}B) — IdP 통합 흔적")
        else:
            lines.append("[자동] OIDC discovery 미노출 — 외부 IdP federation 미확인")

    if "기기" in p or "엔드포인트" in p:
        gh_dockerfile = (gh.get("files") or {}).get("Dockerfile") if gh else None
        if gh_dockerfile:
            lines.append("[자동] GitHub repo Dockerfile 발견 — 컨테이너 기반 배포 추정")

    if "네트워크" in p:
        if http.get("score") is not None:
            assessment = http.get("assessment") or {}
            cors = assessment.get("cors_safe", "?")
            hsts = assessment.get("hsts", "?")
            csp = assessment.get("csp", "?")
            lines.append(
                f"[자동] HTTP 보안 헤더 종합 {http.get('score', 0):.2f}/1.0 "
                f"— HSTS={hsts}, CSP={csp}, CORS={cors}"
            )
            for issue in (http.get("issues") or [])[:3]:
                lines.append(f"  · {issue}")
        if tls.get("verdict"):
            v = tls.get("verdict")
            dr = tls.get("days_remaining", "?")
            lines.append(f"[자동] TLS 인증서 {v} — 만료까지 {dr}일, key={tls.get('key_type','?')} {tls.get('key_bits','?')}bit")
        if dns.get("score") is not None:
            spf_v = (dns.get("spf") or {}).get("verdict", "?")
            dmarc_v = (dns.get("dmarc") or {}).get("verdict", "?")
            caa_v = (dns.get("caa") or {}).get("verdict", "?")
            lines.append(f"[자동] DNS 보안 {dns['score']:.2f}/1.0 — SPF={spf_v}, DMARC={dmarc_v}, CAA={caa_v}")

    if "시스템" in p:
        if expo.get("summary"):
            lines.append(f"[자동] 공개 노출: {expo['summary']}")

    if "애플리케이션" in p or "워크로드" in p:
        if gh and not gh.get("error"):
            score = gh.get("score", 0)
            ci = ", ".join(gh.get("ci_workflows") or [])[:80]
            lines.append(
                f"[자동] GitHub repo 보안 {score:.2f}/1.0 "
                f"— lockfile={'있음' if (gh.get('files') or {}).get('package-lock.json') or (gh.get('files') or {}).get('yarn.lock') else '없음'}, "
                f"SECURITY.md={'있음' if (gh.get('files') or {}).get('SECURITY.md') else '없음'}, "
                f"dependabot={'있음' if (gh.get('files') or {}).get('.github/dependabot.yml') else '없음'}"
            )
            if ci:
                lines.append(f"  · CI workflows: {ci}")
            for issue in (gh.get("issues") or [])[:3]:
                lines.append(f"  · {issue}")

    if "데이터" in p:
        # CSP/CORS 와 RP 정책
        if http.get("findings"):
            rp = http.get("findings", {}).get("referrer_policy", "")
            cors = http.get("findings", {}).get("cors_origin", "")
            if rp or cors:
                lines.append(f"[자동] Referrer-Policy={rp or '(없음)'} · CORS Origin={cors or '(없음)'}")

    return "\n".join(lines) if lines else ""
