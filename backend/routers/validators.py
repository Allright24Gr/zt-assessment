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
# Entra ID tenant_id
# ──────────────────────────────────────────────────────────────────────────────

# Entra tenant_id: GUID(UUID) 형식 또는 *.onmicrosoft.com / 커스텀 도메인 모두 허용.
_ENTRA_TENANT_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ENTRA_TENANT_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$"
)


def validate_entra_tenant_id(value: str, field_name: str = "entra_creds.tenant_id") -> str:
    """tenant_id: UUID(GUID) 또는 도메인 형식. 셸 메타문자 차단."""
    value = (value or "").strip()
    if not value:
        return ""
    if any(c in value for c in _SHELL_METAS + " "):
        raise ValueError(f"{field_name}: 허용되지 않은 문자 포함")
    if _ENTRA_TENANT_UUID_RE.match(value):
        return value
    if _ENTRA_TENANT_DOMAIN_RE.match(value) and "." in value:
        return value
    raise ValueError(f"{field_name}: GUID 또는 도메인 형식이어야 합니다")
