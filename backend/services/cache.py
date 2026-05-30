"""cache.py — 평가 결과/리포트 재사용 캐시 (MAR-016).

스코어링/리포트 생성은 동일 세션에 대해 반복 호출되는데(결과 화면 새로고침,
PDF·증적·판정로그 다운로드 등) 매번 DB 조회 + 직렬화 비용이 든다. 세션이 바뀌지
않는 한(=completed_at/status 동일) 결과를 재사용한다.

- 스레드 안전 TTL 캐시. 키는 호출 측에서 (session_id, completed_at, status) 등
  버전 정보를 포함해 만들기 때문에 세션이 재채점되면 키가 바뀌어 자동 무효화된다.
- hits/misses 통계를 노출(MAR-009 /metrics 에 사용).
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

_lock = threading.Lock()
_store: dict[str, tuple[float, Any]] = {}   # key -> (expire_ts, value)
_stats = {"hits": 0, "misses": 0, "sets": 0, "evictions": 0}

DEFAULT_TTL = 300.0  # 초


def _now() -> float:
    return time.time()


def get(key: str) -> Optional[Any]:
    with _lock:
        item = _store.get(key)
        if item is None:
            _stats["misses"] += 1
            return None
        expire_ts, value = item
        if expire_ts < _now():
            _store.pop(key, None)
            _stats["evictions"] += 1
            _stats["misses"] += 1
            return None
        _stats["hits"] += 1
        return value


def set(key: str, value: Any, ttl: float = DEFAULT_TTL) -> None:
    with _lock:
        _store[key] = (_now() + ttl, value)
        _stats["sets"] += 1
        # 가벼운 정리 — 만료 항목 제거(최대 64개만 스캔하여 비용 제한)
        if len(_store) > 512:
            now = _now()
            for k in list(_store.keys())[:64]:
                if _store[k][0] < now:
                    _store.pop(k, None)
                    _stats["evictions"] += 1


def get_or_set(key: str, producer: Callable[[], Any], ttl: float = DEFAULT_TTL) -> tuple[Any, bool]:
    """(value, hit) 반환. hit=True 면 캐시에서 가져온 것."""
    cached = get(key)
    if cached is not None:
        return cached, True
    value = producer()
    set(key, value, ttl)
    return value, False


def invalidate_prefix(prefix: str) -> int:
    """세션 변경 시 관련 키를 일괄 무효화. 제거 건수 반환."""
    with _lock:
        keys = [k for k in _store if k.startswith(prefix)]
        for k in keys:
            _store.pop(k, None)
        return len(keys)


def stats() -> dict:
    with _lock:
        total = _stats["hits"] + _stats["misses"]
        hit_rate = (_stats["hits"] / total) if total else 0.0
        return {**_stats, "size": len(_store), "hit_rate": round(hit_rate, 4)}
