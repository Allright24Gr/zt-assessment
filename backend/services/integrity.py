"""integrity.py — 위변조 방지 해시 (SER-006 감사 로그 / SER-010 평가 결과).

원리:
  - 각 레코드의 핵심 필드를 정규화(canonical) 문자열로 직렬화한 뒤 SHA-256.
  - 감사 로그는 직전 행의 row_hash 를 prev_hash 로 묶어 **해시 체인**을 만든다.
    중간 행을 변조·삭제하면 그 이후 모든 행의 재계산 결과가 어긋나 탐지된다.
  - 평가 결과는 행 단위 해시. 작성 시점 값으로 고정되므로 DB 에서 result/score 를
    몰래 바꾸면 재계산 해시가 달라져 변조로 판정된다.

해시는 무결성 검증용이며 기밀성과 무관하다(비밀키 없는 SHA-256).
"""
from __future__ import annotations

import hashlib
from typing import Optional


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def audit_row_hash(
    prev_hash: Optional[str],
    *,
    event_type: str,
    user_id: Optional[int],
    login_id: Optional[str],
    source_ip: Optional[str],
    success: int,
    created_at: Optional[str],
) -> str:
    """감사 로그 1행의 체인 해시. prev_hash 가 없으면 빈 문자열로 시작."""
    canonical = "|".join([
        prev_hash or "",
        event_type or "",
        str(user_id if user_id is not None else ""),
        login_id or "",
        source_ip or "",
        str(success),
        created_at or "",
    ])
    return _sha256(canonical)


def result_row_hash(
    *,
    session_id: int,
    check_id: int,
    result: str,
    score: Optional[float],
) -> str:
    """평가 결과 1행 해시 — 작성 시점 (result, score) 고정."""
    score_str = f"{float(score):.6f}" if score is not None else ""
    canonical = "|".join([str(session_id), str(check_id), result or "", score_str])
    return _sha256(canonical)
