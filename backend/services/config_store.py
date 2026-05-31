"""config_store.py — 재시작 없는 동적 운영 설정 (MAR-010).

SystemConfig 테이블에 key-value 로 저장하고 30초 메모리 캐시로 읽는다. DB 에
값이 없으면 환경변수, 그것도 없으면 코드 기본값을 쓴다. admin 이
/api/admin/config 로 값을 바꾸면 캐시를 즉시 비워 다음 조회부터 반영된다(런타임
동적 변경).

화이트리스트(_SPEC)에 등록된 키만 조회·변경 가능 — 임의 키 주입 방지.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# key -> {type, env, default, label}
_SPEC: dict[str, dict] = {
    "session_retention_days": {"type": "int", "env": "ZTA_SESSION_RETENTION_DAYS",
                                "default": 90, "label": "진단 세션 보관 일수"},
    "assessment_sla_seconds": {"type": "int", "env": "ZTA_ASSESSMENT_SLA_SECONDS",
                                "default": 600, "label": "평가 수행 시간 SLA(초)"},
    "collector_retry": {"type": "int", "env": "ZTA_COLLECTOR_RETRY",
                         "default": 3, "label": "collector 재시도 횟수"},
    "demo_delay_ms": {"type": "int", "env": "ZTA_DEMO_DELAY_MS",
                      "default": 0, "label": "데모 진행률 딜레이(ms)"},
    "cleanup_disable": {"type": "bool", "env": "ZTA_CLEANUP_DISABLE",
                        "default": False, "label": "세션 자동 삭제 비활성"},
    "scheduler_enable": {"type": "bool", "env": "ZTA_SCHEDULER_ENABLE",
                         "default": True, "label": "주기 평가 스케줄러 활성"},
    "backup_interval_hours": {"type": "int", "env": "ZTA_BACKUP_INTERVAL_HOURS",
                              "default": 0, "label": "자동 백업 주기(시간, 0=비활성)"},
    "result_cache_ttl": {"type": "int", "env": "ZTA_RESULT_CACHE_TTL",
                         "default": 300, "label": "결과 캐시 TTL(초)"},
}

_CACHE_TTL = 30.0
_lock = threading.Lock()
_cache: dict[str, Any] = {}
_cache_at = 0.0


def _coerce(spec: dict, raw: Any) -> Any:
    t = spec["type"]
    try:
        if t == "int":
            return int(raw)
        if t == "bool":
            if isinstance(raw, bool):
                return raw
            return str(raw).strip().lower() in ("1", "true", "yes", "on")
        return str(raw)
    except Exception:
        return spec["default"]


def _load_from_db(db: Session) -> dict[str, str]:
    from models import SystemConfig
    rows = db.query(SystemConfig).all()
    return {r.config_key: r.config_value for r in rows}


def _refresh(db: Optional[Session]) -> None:
    """DB → 캐시 갱신. db 가 없으면 env/default 만."""
    global _cache_at
    import os
    db_vals: dict[str, str] = {}
    if db is not None:
        try:
            db_vals = _load_from_db(db)
        except Exception as exc:
            logger.warning("[config] DB load 실패 — env/default 사용: %s", exc)
    resolved: dict[str, Any] = {}
    for key, spec in _SPEC.items():
        if key in db_vals and db_vals[key] is not None:
            resolved[key] = _coerce(spec, db_vals[key])
        elif spec["env"] and os.getenv(spec["env"], "") != "":
            resolved[key] = _coerce(spec, os.getenv(spec["env"]))
        else:
            resolved[key] = spec["default"]
    with _lock:
        _cache.clear()
        _cache.update(resolved)
        _cache_at = time.time()


def get(key: str, db: Optional[Session] = None) -> Any:
    if key not in _SPEC:
        raise KeyError(f"unknown config key: {key}")
    with _lock:
        fresh = (time.time() - _cache_at) < _CACHE_TTL and key in _cache
        if fresh:
            return _cache[key]
    _refresh(db)
    with _lock:
        return _cache.get(key, _SPEC[key]["default"])


def get_all(db: Session) -> list[dict]:
    _refresh(db)
    with _lock:
        out = []
        for key, spec in _SPEC.items():
            out.append({
                "key": key,
                "label": spec["label"],
                "type": spec["type"],
                "value": _cache.get(key, spec["default"]),
                "default": spec["default"],
                "env": spec["env"],
            })
        return out


def set_value(db: Session, key: str, value: Any, updated_by: Optional[str] = None) -> Any:
    if key not in _SPEC:
        raise KeyError(f"unknown config key: {key}")
    from models import SystemConfig
    spec = _SPEC[key]
    coerced = _coerce(spec, value)
    row = db.query(SystemConfig).filter(SystemConfig.config_key == key).first()
    if row:
        row.config_value = str(coerced)
        row.updated_by = updated_by
    else:
        db.add(SystemConfig(config_key=key, config_value=str(coerced), updated_by=updated_by))
    db.commit()
    # 캐시 즉시 무효화 → 다음 get 에서 재로딩(런타임 동적 반영).
    with _lock:
        global _cache_at
        _cache_at = 0.0
    return coerced


def known_keys() -> list[str]:
    return list(_SPEC.keys())
