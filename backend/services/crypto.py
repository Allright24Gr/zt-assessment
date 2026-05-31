"""crypto.py — 저장 데이터 at-rest 암호화 (SER-003).

증적 파일(고객 보안 증거)을 디스크에 평문으로 두지 않기 위해 Fernet
(AES-128-CBC + HMAC-SHA256) 대칭 암호화를 사용한다.

키 우선순위:
  1) ZTA_ENCRYPTION_KEY  — Fernet 표준 키(urlsafe base64 32바이트). 운영 권장.
  2) SECRET_KEY / JWT_SECRET 로부터 PBKDF2-SHA256 파생 (고정 salt).
     SECRET_KEY 가 .env 에 고정돼 있으면 재시작 후에도 동일 키가 나와 복호화 가능.

키를 전혀 만들 수 없으면 암호화 비활성(평문 저장)으로 폴백한다 — 기능 자체가
막히지 않도록. is_enabled() 로 상태를 노출한다.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_FERNET = None
_ENABLED = False
_KEY_SOURCE = "none"

# 파생 키용 고정 salt (키 자체는 SECRET_KEY 에서 나오므로 salt 는 공개여도 무방).
_DERIVE_SALT = b"zt-assessment::evidence-at-rest::v1"


def _derive_key(secret: str) -> bytes:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), _DERIVE_SALT, 200_000)
    return base64.urlsafe_b64encode(dk)


def _init() -> None:
    global _FERNET, _ENABLED, _KEY_SOURCE
    try:
        from cryptography.fernet import Fernet
    except Exception as exc:  # pragma: no cover - cryptography 는 requirements 에 있음
        logger.warning("[crypto] cryptography 미설치 — 암호화 비활성: %s", exc)
        return

    raw = os.getenv("ZTA_ENCRYPTION_KEY", "").strip()
    key: Optional[bytes] = None
    if raw:
        try:
            # 유효성 검증 (32바이트 urlsafe b64)
            Fernet(raw.encode())
            key = raw.encode()
            _KEY_SOURCE = "ZTA_ENCRYPTION_KEY"
        except Exception:
            logger.warning("[crypto] ZTA_ENCRYPTION_KEY 형식 오류 — SECRET_KEY 파생으로 폴백")

    if key is None:
        secret = os.getenv("SECRET_KEY", "") or os.getenv("JWT_SECRET", "")
        if secret:
            key = _derive_key(secret)
            _KEY_SOURCE = "SECRET_KEY-derived"

    if key is None:
        logger.warning("[crypto] 암호화 키 없음 — 증적 파일 평문 저장으로 폴백")
        return

    _FERNET = Fernet(key)
    _ENABLED = True


_init()


def is_enabled() -> bool:
    return _ENABLED


def key_source() -> str:
    return _KEY_SOURCE


def encrypt_bytes(data: bytes) -> tuple[bytes, bool]:
    """(저장할 바이트, encrypted 여부) 반환. 비활성/실패 시 평문 그대로."""
    if not _ENABLED or _FERNET is None:
        return data, False
    try:
        return _FERNET.encrypt(data), True
    except Exception as exc:
        logger.warning("[crypto] encrypt 실패 — 평문 저장: %s", exc)
        return data, False


def decrypt_bytes(data: bytes) -> bytes:
    """암호문 → 평문. 실패 시 원본 그대로 반환(과거 평문 파일 호환)."""
    if not _ENABLED or _FERNET is None:
        return data
    try:
        return _FERNET.decrypt(data)
    except Exception:
        # 평문 파일이 들어오면 decrypt 가 InvalidToken — 원본을 그대로 반환.
        return data
