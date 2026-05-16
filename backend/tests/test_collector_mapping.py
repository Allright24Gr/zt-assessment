"""collector 매핑 회귀 방지 — 도구별 자동 매핑 개수 + item_id 유일성 검증.

명시 매핑(_BASE_MAPPING_FNS) + collect_* docstring 기반 autodiscover 의 합산이
collectors 모듈에 정의된 `collect_*` 함수 개수와 일치해야 한다.
"""
from __future__ import annotations

import pytest

from routers.assessment import _full_mapping


@pytest.mark.parametrize(
    "tool,expected",
    [
        ("keycloak", 65),
        ("wazuh",   122),
        ("nmap",     14),
        ("trivy",    11),
        ("entra",    20),
        ("okta",     15),
        ("splunk",   15),
    ],
)
def test_full_mapping_count(tool, expected):
    items = _full_mapping(tool)
    assert len(items) == expected, (
        f"{tool}: expected {expected}, got {len(items)}. "
        f"collector 모듈에 collect_* 함수가 추가/삭제됐다면 매핑 또는 docstring을 점검하세요."
    )


@pytest.mark.parametrize(
    "tool", ["keycloak", "wazuh", "nmap", "trivy", "entra", "okta", "splunk"],
)
def test_item_id_unique_within_tool(tool):
    items = _full_mapping(tool)
    iids = [i[1] for i in items]
    assert len(iids) == len(set(iids)), (
        f"{tool}: 중복된 item_id 발견 — {[x for x in iids if iids.count(x) > 1]}"
    )
