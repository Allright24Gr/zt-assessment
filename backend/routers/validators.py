"""사용자 입력 검증 — scan_targets / Keycloak·Wazuh 자격 URL.

각 검증 함수는 입력을 strip 한 뒤 빈 문자열이면 그대로 빈 문자열을 반환한다.
형식 위반/쉘 메타문자 포함 시 ValueError. 호출 측은 ValueError를 잡아
HTTPException(400)으로 변환할 책임을 가진다.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


# ──────────────────────────────────────────────────────────────────────────────
# nmap target
# ──────────────────────────────────────────────────────────────────────────────

# IPv4 단일/CIDR, 도메인(영문/숫자/하이픈/점) 허용. 공백/쉘 메타문자 차단.
_NMAP_TARGET_RE = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"             # IPv4 [+CIDR]
    r"|[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?"  # domain
    r")$"
)

# 셸 메타문자 (목록은 nmap/trivy 공통). 두 검증 함수에서 동일하게 사용.
_SHELL_METAS = ";|&`$<>\\\"'"


def validate_nmap_target(target: str) -> str:
    """공백 strip 후 형식 검증. 실패 시 ValueError. 빈 문자열은 빈 문자열 반환."""
    target = (target or "").strip()
    if not target:
        return ""
    if not _NMAP_TARGET_RE.match(target):
        raise ValueError(f"유효하지 않은 nmap 대상: {target!r} (IPv4/CIDR/도메인만 허용)")
    if any(c in target for c in _SHELL_METAS):
        raise ValueError("대상에 허용되지 않은 문자가 포함되어 있습니다.")
    return target


# ──────────────────────────────────────────────────────────────────────────────
# trivy image
# ──────────────────────────────────────────────────────────────────────────────

# 컨테이너 이미지 참조 규약: registry/namespace/repo:tag@digest 등 다양.
# 보수적으로 영문/숫자/일부 기호만 허용.
_TRIVY_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]{0,254}$")


def validate_trivy_image(image: str) -> str:
    image = (image or "").strip()
    if not image:
        return ""
    if not _TRIVY_IMAGE_RE.match(image):
        raise ValueError(f"유효하지 않은 trivy 이미지: {image!r}")
    if any(c in image for c in _SHELL_METAS + " "):
        raise ValueError("이미지 이름에 허용되지 않은 문자가 포함되어 있습니다.")
    return image


# trivy repo: GitHub URL 또는 owner/repo 단축형
_TRIVY_REPO_RE = re.compile(
    r"^(?:https://github\.com/)?"
    r"[a-zA-Z0-9][a-zA-Z0-9._\-]{0,99}/[a-zA-Z0-9][a-zA-Z0-9._\-]{0,99}"
    r"(?:\.git)?/?$"
)


def validate_trivy_repo(repo: str) -> str:
    """GitHub repo URL 또는 owner/name 단축형. 공백/메타문자 차단."""
    repo = (repo or "").strip()
    if not repo:
        return ""
    if any(c in repo for c in _SHELL_METAS + " "):
        raise ValueError("repo 입력에 허용되지 않은 문자가 포함되어 있습니다.")
    if not _TRIVY_REPO_RE.match(repo):
        raise ValueError(
            f"유효하지 않은 trivy repo: {repo!r} "
            f"(예: https://github.com/owner/repo 또는 owner/repo)"
        )
    return repo


def _looks_like_repo_shorthand(target: str) -> bool:
    if "://" in target:
        return False
    if ":" in target or "@" in target:
        return False
    return target.count("/") == 1


def validate_trivy_target(target: str) -> str:
    """이미지 또는 GitHub repo 두 형식 모두 허용. 형식 자동 판별."""
    target = (target or "").strip()
    if not target:
        return ""
    if "github.com" in target.lower() or _looks_like_repo_shorthand(target):
        return validate_trivy_repo(target)
    return validate_trivy_image(target)


# ──────────────────────────────────────────────────────────────────────────────
# Keycloak / Wazuh URL
# ──────────────────────────────────────────────────────────────────────────────

def validate_https_url(url: str, field_name: str = "url") -> str:
    """http/https 스킴 + hostname 존재만 보장. 빈 문자열은 그대로 통과."""
    url = (url or "").strip()
    if not url:
        return ""
    try:
        p = urlparse(url)
    except Exception:
        raise ValueError(f"{field_name}: URL 파싱 실패")
    if p.scheme not in ("http", "https"):
        raise ValueError(f"{field_name}: http/https 만 허용")
    if not p.hostname:
        raise ValueError(f"{field_name}: 호스트 누락")
    return url


# ──────────────────────────────────────────────────────────────────────────────
# web_probe target (도메인 또는 https URL)
# ──────────────────────────────────────────────────────────────────────────────

# 도메인: 영문/숫자/하이픈/점, 양 끝 영문/숫자. URL 은 https/http 허용.
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$"
)


def validate_web_probe_target(target: str) -> str:
    """web_probe 대상: 도메인 또는 http(s) URL. CIDR/IP 단독은 허용하지 않음.

    web_probe 는 HTTP/TLS/OIDC/DNS/CT 를 도메인 단위로 측정하므로 도메인 또는
    스킴 포함 URL 만 의미가 있다. nmap 처럼 CIDR/IP 도 받지 않는다.
    """
    target = (target or "").strip()
    if not target:
        return ""
    if any(c in target for c in _SHELL_METAS + " "):
        raise ValueError("web_probe 대상에 허용되지 않은 문자가 포함되어 있습니다.")
    if "://" in target:
        # URL 형식 — validate_https_url 재사용
        return validate_https_url(target, "web_probe target")
    # 도메인 형식 — 점이 최소 1개 있어야 hostname 으로 의미가 있다.
    if "." not in target:
        raise ValueError(f"유효하지 않은 web_probe 도메인: {target!r} (예: example.com)")
    if not _DOMAIN_RE.match(target):
        raise ValueError(f"유효하지 않은 web_probe 도메인: {target!r}")
    return target


# ──────────────────────────────────────────────────────────────────────────────
# 자격(admin_user / admin_pass) 길이 검증
# ──────────────────────────────────────────────────────────────────────────────

def validate_cred_field(value: str, field_name: str, max_len: int = 100) -> str:
    """공백 strip 후 길이만 체크. 빈 값은 그대로 통과 (선택 입력)."""
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > max_len:
        raise ValueError(f"{field_name}: {max_len}자 이내여야 합니다 ({len(value)}자 입력)")
    return value


# ──────────────────────────────────────────────────────────────────────────────
